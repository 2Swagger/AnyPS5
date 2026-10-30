#include "prx/libSceLibreSsl/include/ObjectTable.hpp"
#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libc/include/General.hpp"
#include <bit>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr int ObjectLibrary = 8;
constexpr int Asn1Library = 13;
constexpr int AnyFunction = 0xfff;
constexpr int UnknownNid = 101;
constexpr int FirstNumberTooLarge = 122;
constexpr int InvalidDigit = 130;
constexpr int InvalidSeparator = 131;
constexpr int MissingSecondNumber = 138;
constexpr int SecondNumberTooLarge = 147;
constexpr std::uint64_t BigNumberThreshold = (UINT64_MAX - 80) / 10;

struct AddedObject {
    LibreSslAsn1Object object{};
    std::vector<unsigned char> data;
    std::optional<std::string> shortName;
    std::optional<std::string> longName;
};

std::mutex mutex;
bool tableExists = false;
int nextNid = LibreSslObjectCount;
std::vector<std::unique_ptr<AddedObject>> objects;
std::map<std::vector<unsigned char>, const AddedObject*> byData;
std::map<int, const AddedObject*> byNid;

void Asn1Error(int reason) {
    LibreSslPutError_nid_no_patch(Asn1Library, AnyFunction, reason);
}

class Arc {
public:
    explicit Arc(std::uint64_t value) : limbs{static_cast<std::uint32_t>(value), static_cast<std::uint32_t>(value >> 32)} {}

    void MultiplyAdd(std::uint32_t factor, std::uint32_t addend) {
        std::uint64_t carry = addend;
        for (auto& limb : limbs) {
            const std::uint64_t product = static_cast<std::uint64_t>(limb) * factor + carry;
            limb = static_cast<std::uint32_t>(product);
            carry = product >> 32;
        }
        if (carry) limbs.push_back(static_cast<std::uint32_t>(carry));
    }

    int Bits() const {
        for (std::size_t index = limbs.size(); index-- > 0;) {
            if (limbs[index]) return static_cast<int>(index * 32) + 32 - std::countl_zero(limbs[index]);
        }
        return 0;
    }

    unsigned char DivideBy128() {
        std::uint64_t remainder = 0;
        for (std::size_t index = limbs.size(); index-- > 0;) {
            const std::uint64_t current = (remainder << 32) | limbs[index];
            limbs[index] = static_cast<std::uint32_t>(current / 128);
            remainder = current % 128;
        }
        return static_cast<unsigned char>(remainder);
    }

private:
    std::vector<std::uint32_t> limbs;
};

std::vector<unsigned char> TextToContent(const char* text) {
    std::vector<unsigned char> out;
    std::size_t remaining = std::strlen(text);
    const char* next = text;
    int character = static_cast<signed char>(*next++);
    if (character < '0' || character > '2') {
        Asn1Error(FirstNumberTooLarge);
        return {};
    }
    --remaining;
    const int first = character - '0';
    if (!remaining) {
        Asn1Error(MissingSecondNumber);
        return {};
    }
    character = static_cast<signed char>(*next++);
    --remaining;
    while (remaining) {
        if (character != '.' && character != ' ') {
            Asn1Error(InvalidSeparator);
            return {};
        }
        std::uint64_t value = 0;
        std::optional<Arc> big;
        while (remaining) {
            --remaining;
            character = static_cast<signed char>(*next++);
            if (character == ' ' || character == '.') break;
            if (character < '0' || character > '9') {
                Asn1Error(InvalidDigit);
                return {};
            }
            if (!big && value >= BigNumberThreshold) big.emplace(value);
            if (big) big->MultiplyAdd(10, static_cast<std::uint32_t>(character - '0'));
            else value = value * 10 + static_cast<std::uint64_t>(character - '0');
        }
        if (out.empty()) {
            if (first < 2 && value >= 40) {
                Asn1Error(SecondNumberTooLarge);
                return {};
            }
            if (big) big->MultiplyAdd(1, static_cast<std::uint32_t>(first * 40));
            else value += static_cast<std::uint64_t>(first) * 40;
        }
        std::vector<unsigned char> groups;
        if (big) {
            for (int count = (big->Bits() + 6) / 7; count > 0; --count) groups.push_back(big->DivideBy128());
        } else {
            do {
                groups.push_back(static_cast<unsigned char>(value & 0x7f));
                value >>= 7;
            } while (value);
        }
        for (std::size_t index = groups.size(); index-- > 1;) out.push_back(groups[index] | 0x80);
        out.push_back(groups[0]);
    }
    return out;
}

} // namespace

extern "C" {

int LibreSslAddedObjectNid_nid_no_patch(const LibreSslAsn1Object* object) {
    std::lock_guard lock(mutex);
    if (!tableExists || !object->data || object->length <= 0) return 0;
    const auto found = byData.find(std::vector<unsigned char>(object->data, object->data + object->length));
    return found == byData.end() ? 0 : found->second->object.nid;
}

const char* LibreSslAddedObjectName_nid_no_patch(int nid, bool longName) {
    std::lock_guard lock(mutex);
    if (!tableExists) return nullptr;
    const auto found = byNid.find(nid);
    if (found == byNid.end()) {
        LibreSslPutError_nid_no_patch(ObjectLibrary, AnyFunction, UnknownNid);
        return nullptr;
    }
    return longName ? found->second->object.longName : found->second->object.shortName;
}

int APS5_VABI OBJ_create_nid_postfix(const char* oid, const char* shortName, const char* longName) {
    if (!oid) throw std::invalid_argument("OBJ_create: null OID text");
    std::vector<unsigned char> content = TextToContent(oid);
    if (content.empty()) return 0;
    auto added = std::make_unique<AddedObject>();
    added->data = std::move(content);
    if (shortName) added->shortName = shortName;
    if (longName) added->longName = longName;
    std::lock_guard lock(mutex);
    added->object = {added->shortName ? added->shortName->c_str() : nullptr, added->longName ? added->longName->c_str() : nullptr, nextNid++,
        static_cast<std::int32_t>(added->data.size()), added->data.data(), 0};
    tableExists = true;
    byData[added->data] = added.get();
    byNid[added->object.nid] = added.get();
    objects.push_back(std::move(added));
    return objects.back()->object.nid;
}

void APS5_VABI OBJ_cleanup_nid_postfix(void) {
    std::lock_guard lock(mutex);
    byData.clear();
    byNid.clear();
    objects.clear();
    tableExists = false;
}

}
