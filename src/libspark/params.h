#ifndef FIRO_LIBSPARK_PARAMS_H
#define FIRO_LIBSPARK_PARAMS_H

#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>
#include <serialize.h>
#include <sync.h>

using namespace secp_primitives;

namespace spark {

class Params {
public:
    static Params const* get_default();

    const GroupElement& get_F() const;
    const GroupElement& get_G() const;
    const GroupElement& get_H() const;
    const GroupElement& get_U() const;

    std::size_t get_N_range() const;
    std::size_t get_max_M_range() const;
    const std::vector<GroupElement>& get_G_range() const;
    const std::vector<GroupElement>& get_H_range() const;

    std::size_t get_n_grootle() const;
    std::size_t get_m_grootle() const;
    const std::vector<GroupElement>& get_G_grootle() const;

private:
    Params(const GroupElement&, const GroupElement&, const GroupElement&, const GroupElement&, std::size_t, std::size_t, std::size_t, std::size_t);

private:
    static CCriticalSection cs_instance;
    static std::unique_ptr<Params> instance;

    // Global protocol parameters
    GroupElement F;
    GroupElement G;
    GroupElement H;
    GroupElement U;

    // Range proof parameters
    std::size_t N_range;
    std::size_t max_M_range;
    std::vector<GroupElement> G_range, H_range;

    // One-of-many matrix generators
    std::size_t n_grootle, m_grootle;
    std::vector<GroupElement> G_grootle;
};

}

#endif
