#include <math.h>
namespace aura {
template<class Exponent, class GroupElement>
class HOOMVerifier{

    template<class Exponent, class GroupElement>
    HOOMVerifier(const GroupElement& g,
                        const std::vector<GroupElement>& h_gens,
                        int t_n, int t_m, int m_n, int m_m)
            : g_(g)
            , h_(h_gens)
            , t_n_(t_n)
            , t_m_(t_m)
            , m_n_(m_n)
            , m_m_(m_m) {
    }

    template<class Exponent, class GroupElement>
    bool verify(const std::vector<GroupElement>& commits
                      const std::vector<SigmaPlusProof<Exponent, GroupElement>>& proof){
        int t_ = pow(t_n_, t_m_);
        int m_ = pow(m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> d_verifier(g, h_gens, m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar,secp_primitives::GroupElement> D_verifier(g, h_gens, t_n_, t_m_);

        std::vector<GroupElement> group_elements = {g, h_[0] * t_n_, h_[0] * t_m_, h_[0] * m_n_, h_[0] * m_m_};
        group_elements.insert(group_elements.end(), proof.d_.begin(), proof.d_.end());
        proof_out.D_Proof_.resize(t_);
        for (int k = 0; k < m_; ++k) {
            SigmaPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x[k]);
            group_elements.pushback(h_[0] * x[k]);
        }
        std::vector<GroupElement> C_;
        C_.resize(m_);
        std::vector<GroupElement> D_;
        D_.resize(t_);
        GroupElement D;
        D = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(proof_out.d_, x);
        for (int k = 0; k < t_; ++k) {
            std::copy(commits.begin() + k * m_, commits.begin() + (k + 1) * m_ - 1, C_.begin())
            D_[k] = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(C_, x) + D * -1;
        }
        return d_verifier.verify(proof.d_, proof.d_Proof_, true) && D_verifier.verify(D_, proof.D_Proof_, true);
    }
};

} // namespace aura
