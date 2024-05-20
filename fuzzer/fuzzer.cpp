#include <cstdint>
#include <Gadgify.h>
#include <ExecutableBinary.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size <= 1)
    {
        return 1;
    }
    std::vector<char> binary(Data, Data+Size);
    Gadgify::GetGadgets([](uint64_t offset, const std::string &gadget) {
                            return;
                        },
                        binary,
                        "ret;",
                        2,
                        true
                        );
    return 0;
}