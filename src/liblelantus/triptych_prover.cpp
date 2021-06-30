#include "triptych_prover.h"

namespace lelantus {

TriptychProver::TriptychProver(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        const GroupElement& u,
        std::size_t n,
        std::size_t m)
        : g_(g)
        , h_(h_gens)
        , u_(u)
        , n_(n)
        , m_(m) {
}

// Generate a one-of-many proof
void TriptychProver::triptych_prove(
        const std::vector<GroupElement>& commits,
        const std::vector<GroupElement>& amount_commits,
        const GroupElement& offset,
        std::size_t l,
        const Scalar& r,
        const Scalar& s,
        TriptychProof& proof_out) {
    // Sanity checks
    if (n_ < 2 || m_ < 2) {
        throw std::invalid_argument("Prover parameters are invalid");
    }
    std::size_t N = (std::size_t)pow(n_, m_);
    std::size_t setSize = commits.size();
    if (setSize == 0) {
        throw std::invalid_argument("Cannot have empty commitment set");
    }
    if (amount_commits.size() != setSize) {
        throw std::invalid_argument("Amount commitment set size is invalid");
    }
    if (setSize > N) {
        throw std::invalid_argument("Commitment set is too large");
    }
    if (l >= setSize) {
        throw std::invalid_argument("Signing index is out of range");
    }
    if (h_.size() != n_ * m_) {
        throw std::invalid_argument("Generator vector size is invalid");
    }
    if (commits[l] != g_ * r) {
        throw std::invalid_argument("Bad known commitment");
    }
    const Scalar MINUS_ONE = Scalar(uint64_t(0)) - Scalar(uint64_t(1));
    if (amount_commits[l] + offset * MINUS_ONE != g_ * s) {
        throw std::invalid_argument("Bad known amount commitment or offset");
    }

    // Linking tag (and auxiliary tag)
    proof_out.J_ = u_ * r.inverse();
    proof_out.K_ = proof_out.J_ * s;

    std::vector<Scalar> sigma;
    LelantusPrimitives::convert_to_sigma(l, n_, m_, sigma);
    std::vector<Scalar> rho;
    rho.resize(m_);
    for (std::size_t j = 0; j < m_; ++j)
    {
        rho[j].randomize();
    }

    //compute B
    Scalar rB;
    rB.randomize();
    LelantusPrimitives::commit(g_, h_, sigma, rB, proof_out.B_);

    //compute A
    std::vector<Scalar> a;
    a.resize(m_ * n_);
    for (std::size_t j = 0; j < m_; ++j)
    {
        for (std::size_t i = 1; i < n_; ++i)
        {
            a[j * n_ + i].randomize();
            a[j * n_] -= a[j * n_ + i];
        }
    }
    Scalar rA;
    rA.randomize();
    LelantusPrimitives::commit(g_, h_, a, rA, proof_out.A_);

    //compute C
    std::vector<Scalar> c;
    c.resize(n_ * m_);
    Scalar one(uint64_t(1));
    Scalar two(uint64_t(2));
    for (std::size_t i = 0; i < n_ * m_; ++i)
    {
        c[i] = a[i] * (one - two * sigma[i]);
    }
    Scalar rC;
    rC.randomize();
    LelantusPrimitives::commit(g_, h_, c, rC, proof_out.C_);

    //compute D
    std::vector<Scalar> d;
    d.resize(n_ * m_);
    for (std::size_t i = 0; i < n_ * m_; i++)
    {
        d[i] = a[i].square().negate();
    }
    Scalar rD;
    rD.randomize();
    LelantusPrimitives::commit(g_,h_, d, rD, proof_out.D_);

    std::vector<std::vector<Scalar>> P_i_k;
    P_i_k.resize(setSize);
    for (std::size_t k = 0; k < setSize - 1; ++k)
    {
        std::vector<Scalar>& coefficients = P_i_k[k];
        std::vector<std::size_t> I = LelantusPrimitives::convert_to_nal(k, n_, m_);
        coefficients.push_back(a[I[0]]);
        coefficients.push_back(sigma[I[0]]);
        for (std::size_t j = 1; j < m_; ++j) {
            LelantusPrimitives::new_factor(sigma[j * n_ + I[j]], a[j * n_ + I[j]], coefficients);
        }
    }

    /*
     * To optimize calculation of sum of all polynomials indices 's' = setSize-1 through 'n^m-1' we use the
     * fact that sum of all of elements in each row of 'a' array is zero. Computation is done by going
     * through n-ary representation of 's' and increasing "digit" at each position to 'n-1' one by one.
     * During every step digits at higher positions are fixed and digits at lower positions go through all
     * possible combinations with a total corresponding polynomial sum of 'x^j'.
     *
     * The math behind optimization (TeX notation):
     *
     * \sum_{i=s+1}^{N-1}p_i(x) =
     *   \sum_{j=0}^{m-1}
     *     \left[
     *       \left( \sum_{i=s_j+1}^{n-1}(\delta_{l_j,i}x+a_{j,i}) \right)
     *       \left( \prod_{k=j}^{m-1}(\delta_{l_k,s_k}x+a_{k,s_k}) \right)
     *       x^j
     *     \right]
     */

    std::vector<std::size_t> I = LelantusPrimitives::convert_to_nal(setSize - 1, n_, m_);
    std::vector<std::size_t> lj = LelantusPrimitives::convert_to_nal(l, n_, m_);

    std::vector<Scalar> p_i_sum;
    p_i_sum.emplace_back(one);
    std::vector<std::vector<Scalar>> partial_p_s;

    // Pre-calculate product parts and calculate p_s(x) at the same time, put the latter into p_i_sum
    for (std::size_t j = m_; j > 0; j--) {
        partial_p_s.push_back(p_i_sum);
        LelantusPrimitives::new_factor(sigma[(j - 1) * n_ + I[j - 1]], a[(j - 1) * n_ + I[j - 1]], p_i_sum);
    }

    for (std::size_t j = 0; j < m_; j++) {
        // \sum_{i=s_j+1}^{n-1}(\delta_{l_j,i}x+a_{j,i})
        Scalar a_sum(uint64_t(0));
        for (std::size_t i = I[j] + 1; i < n_; i++)
            a_sum += a[j * n_ + i];
        Scalar x_sum(uint64_t(lj[j] >= I[j]+1 ? 1 : 0));

        // Multiply by \prod_{k=j}^{m-1}(\delta_{l_k,s_k}x+a_{k,s_k})
        std::vector<Scalar> &polynomial = partial_p_s[m_ - j - 1];
        LelantusPrimitives::new_factor(x_sum, a_sum, polynomial);

        // Multiply by x^j and add to the result
        for (std::size_t k = 0; k < m_ - j; k++)
            p_i_sum[j + k] += polynomial[k];
    }

    P_i_k[setSize - 1] = p_i_sum;

    proof_out.X_.reserve(m_);
    proof_out.Y_.reserve(m_);

    Scalar mu;
    LelantusPrimitives::generate_triptych_mu(proof_out, offset, mu);

    // Prepare multiexp vectors
    std::vector<GroupElement> X_multiexp_points;
    std::vector<Scalar> X_multiexp_scalars;
    X_multiexp_points.reserve(2*setSize + 2);
    X_multiexp_points.resize(2*setSize + 2);
    X_multiexp_scalars.reserve(2*setSize + 2);
    X_multiexp_scalars.resize(2*setSize + 2);
    for (std::size_t k = 0; k < setSize; k++) {
        X_multiexp_points[2*k] = commits[k];
        X_multiexp_points[2*k + 1] = amount_commits[k];
    }
    X_multiexp_points[2*setSize] = g_;
    X_multiexp_points[2*setSize + 1] = offset;

    for (std::size_t j = 0; j < m_; ++j)
    {
        Scalar offset_scalar(uint64_t(0));
        for (std::size_t k = 0; k < setSize; ++k){
            X_multiexp_scalars[2*k] = P_i_k[k][j];
            X_multiexp_scalars[2*k + 1] = P_i_k[k][j] * mu;
            offset_scalar -= P_i_k[k][j] * mu;
        }
        X_multiexp_scalars[2*setSize] = rho[j];
        X_multiexp_scalars[2*setSize + 1] = offset_scalar;

        secp_primitives::MultiExponent mult(X_multiexp_points, X_multiexp_scalars);
        proof_out.X_.emplace_back(mult.get_multiple());
        proof_out.Y_.emplace_back(proof_out.J_ * rho[j]);
    }

    Scalar x;
    LelantusPrimitives::generate_triptych_x(proof_out, mu, x);

    //f
    proof_out.f_.reserve(m_ * (n_ - 1));
    for (std::size_t j = 0; j < m_; j++)
    {
        for (std::size_t i = 1; i < n_; i++)
            proof_out.f_.emplace_back(sigma[(j * n_) + i] * x + a[(j * n_) + i]);
    }
    //zA, zC
    proof_out.zA_ =  rB * x + rA;
    proof_out.zC_ = rC * x + rD;

    //computing z
    proof_out.z_ = Scalar(uint64_t(0));

    NthPower x_k(x);
    for (std::size_t j = 0; j < m_; ++j) {
        proof_out.z_ -= rho[j] * x_k.pow;
        x_k.go_next();
    }
    proof_out.z_ += (r + mu * s) * x_k.pow;
}

}//namespace lelantus