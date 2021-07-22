#include "parallel_verifier.h"
#include "util.h"
#include <random>

namespace lelantus {

ParallelVerifier::ParallelVerifier(
        const GroupElement& g,
        const GroupElement& h,
        const std::vector<GroupElement>& h_gens,
        std::size_t n,
        std::size_t m)
        : g_(g)
        , h_(h)
        , h_gens(h_gens)
        , n(n)
        , m(m){
}

// Verify a single one-of-many proof
// In this case, there is an implied input set size
bool ParallelVerifier::singleverify(
        const std::vector<GroupElement>& commits_S,
        const std::vector<GroupElement>& commits_V,
        const GroupElement& offset_S,
        const GroupElement& offset_V,
        const Scalar& x,
        const ParallelProof& proof) const {
    std::vector<Scalar> challenges = { x };
    std::vector<GroupElement> offsets_S = { offset_S };
    std::vector<GroupElement> offsets_V = { offset_V };
    std::vector<std::size_t> setSizes = { };
    std::vector<ParallelProof> proofs = { proof };

    return verify(
        commits_S,
        commits_V,
        offsets_S,
        offsets_V,
        challenges,
        setSizes,
        true,
        false,
        proofs
    );
}

// Verify a single one-of-many proof
// In this case, there is a specified set size
bool ParallelVerifier::singleverify(
        const std::vector<GroupElement>& commits_S,
        const std::vector<GroupElement>& commits_V,
        const GroupElement& offset_S,
        const GroupElement& offset_V,
        const Scalar& x,
        const std::size_t setSize,
        const ParallelProof& proof) const {
    std::vector<Scalar> challenges = { x };
    std::vector<GroupElement> offsets_S = { offset_S };
    std::vector<GroupElement> offsets_V = { offset_V };
    std::vector<std::size_t> setSizes = { setSize };
    std::vector<ParallelProof> proofs = { proof };

    return verify(
        commits_S,
        commits_V,
        offsets_S,
        offsets_V,
        challenges,
        setSizes,
        true,
        true,
        proofs
    );
}

// Verify a batch of one-of-many proofs from the same transaction
// In this case, there is a single common challenge and implied input set size
bool ParallelVerifier::batchverify(
        const std::vector<GroupElement>& commits_S,
        const std::vector<GroupElement>& commits_V,
        const std::vector<GroupElement>& offsets_S,
        const std::vector<GroupElement>& offsets_V,
        const Scalar& x,
        const std::vector<ParallelProof>& proofs) const {
    std::vector<Scalar> challenges = { x };
    std::vector<std::size_t> setSizes = { };

    return verify(
        commits_S,
        commits_V,
        offsets_S,
        offsets_V,
        challenges,
        setSizes,
        true,
        false,
        proofs
    );
}

// Verify a general batch of one-of-many proofs
// In this case, each proof has a separate challenge and specified set size
bool ParallelVerifier::batchverify(
        const std::vector<GroupElement>& commits_S,
        const std::vector<GroupElement>& commits_V,
        const std::vector<GroupElement>& offsets_S,
        const std::vector<GroupElement>& offsets_V,
        const std::vector<Scalar>& challenges,
        const std::vector<std::size_t>& setSizes,
        const std::vector<ParallelProof>& proofs) const {

    return verify(
        commits_S,
        commits_V,
        offsets_S,
        offsets_V,
        challenges,
        setSizes,
        false,
        true,
        proofs
    );
}

// Verify a batch of one-of-many proofs
bool ParallelVerifier::verify(
        const std::vector<GroupElement>& commits_S,
        const std::vector<GroupElement>& commits_V,
        const std::vector<GroupElement>& offsets_S,
        const std::vector<GroupElement>& offsets_V,
        const std::vector<Scalar>& challenges,
        const std::vector<std::size_t>& setSizes,
        const bool commonChallenge,
        const bool specifiedSetSizes,
        const std::vector<ParallelProof>& proofs) const {
    // Sanity checks
    if (n < 2 || m < 2) {
        LogPrintf("Verifier parameters are invalid");
        return false;
    }
    std::size_t M = proofs.size();
    std::size_t N = (std::size_t)pow(n, m);

    if (commits_S.size() == 0) {
        LogPrintf("Cannot have empty commitment set");
        return false;
    }
    if (commits_S.size() > N) {
        LogPrintf("Commitment set is too large");
        return false;
    }
    if (commits_S.size() != commits_V.size()) {
        LogPrintf("Commitment set sizes do not match");
        return false;
    }
    if (h_gens.size() != n * m) {
        LogPrintf("Generator vector size is invalid");
        return false;
    }
    if (offsets_S.size() != M || offsets_V.size() != M) {
        LogPrintf("Invalid number of offsets provided");
        return false;
    }

    // For separate challenges, we must have enough
    if (!commonChallenge && challenges.size() != M) {
        LogPrintf("Invalid challenge vector size");
        return false;
    }

    // If we have specified set sizes, we must have enough
    if (specifiedSetSizes && setSizes.size() != M) {
        LogPrintf("Invalid set size vector size");
        return false;
    }

    // All proof elements must be valid
    for (std::size_t t = 0; t < M; ++t) {
        if (!membership_checks(proofs[t])) {
            LogPrintf("Sigma verification failed due to membership checks failed.");
            return false;
        }
    }

    // Commitment binding weight; intentionally restricted range for efficiency
    // NOTE: this may initialize with a PRNG, which should be sufficient for this use
    std::random_device generator;
    std::uniform_int_distribution<uint16_t> distribution;
    Scalar bind_weight(distribution(generator));

    // Bind the commitment lists
    std::vector<GroupElement> commits;
    commits.reserve(commits_S.size());
    for (std::size_t i = 0; i < commits_S.size(); i++) {
        commits.emplace_back(commits_S[i] + commits_V[i] * bind_weight);
    }

    // Final batch multiscalar multiplication
    Scalar g_scalar = Scalar(uint64_t(0)); // associated to g_
    Scalar h_scalar = Scalar(uint64_t(0)); // associated to h1
    std::vector<Scalar> h_scalars; // associated to (h_)
    std::vector<Scalar> commit_scalars; // associated to commitment lists
    h_scalars.reserve(n * m);
    h_scalars.resize(n * m);
    commit_scalars.reserve(commits.size());
    commit_scalars.resize(commits.size());

    // Set up the final batch elements
    std::vector<GroupElement> points;
    std::vector<Scalar> scalars;
    std::size_t final_size = 2 + m * n + commits.size(); // g, h1, (h_), (commits)
    for (std::size_t t = 0; t < M; t++) {
        final_size += 4 + proofs[t].Gk_.size() + proofs[t].Qk_.size(); // A, B, C, D, (G), (Q)
    }
    points.reserve(final_size);
    scalars.reserve(final_size);

    // Index decomposition, which is common among all proofs
    std::vector<std::vector<std::size_t> > I_;
    I_.reserve(commits.size());
    I_.resize(commits.size());
    for (std::size_t i = 0; i < commits.size(); i++) {
        I_[i] = LelantusPrimitives::convert_to_nal(i, n, m);
    }

    // Process all proofs
    for (std::size_t t = 0; t < M; t++) {
        ParallelProof proof = proofs[t];

        // The challenge depends on whether or not we're in common mode
        Scalar x;
        if (commonChallenge) {
            x = challenges[0];
        }
        else {
            x = challenges[t];
        }

        // Generate random verifier weights
        Scalar w1, w2, w3;
        w1.randomize();
        w2.randomize();
        w3.randomize();

        // Reconstruct f-matrix
        std::vector<Scalar> f_;
        if (!compute_fs(proof, x, f_)) {
            LogPrintf("Invalid matrix reconstruction");
            return false;
        }

        // Effective set size
        std::size_t setSize;
        if (!specifiedSetSizes) {
            setSize = commits_S.size();
        }
        else {
            setSize = setSizes[t];
        }

        // A, B, C, D (and associated commitments)
        points.emplace_back(proof.A_);
        scalars.emplace_back(w1.negate());
        points.emplace_back(proof.B_);
        scalars.emplace_back(x.negate() * w1);
        points.emplace_back(proof.C_);
        scalars.emplace_back(x.negate() * w2);
        points.emplace_back(proof.D_);
        scalars.emplace_back(w2.negate());

        g_scalar += proof.ZA_ * w1 + proof.ZC_ * w2;
        for (std::size_t i = 0; i < m * n; i++) {
            h_scalars[i] += f_[i] * (w1 + (x - f_[i]) * w2);
        }

        // Input sets
        h_scalar += (proof.zS_ + bind_weight * proof.zV_) * w3.negate();

        Scalar f_sum;
        Scalar f_i(uint64_t(1));
        std::vector<Scalar>::iterator ptr;
        if (!specifiedSetSizes) {
            ptr = commit_scalars.begin();
            compute_batch_fis(f_sum, f_i, m, f_, w3, ptr, ptr, ptr + setSize - 1);
        }
        else {
            ptr = commit_scalars.begin() + commits.size() - setSize;
            compute_batch_fis(f_sum, f_i, m, f_, w3, ptr, ptr, ptr + setSize - 1);
        }

        Scalar pow(uint64_t(1));
        std::vector<Scalar> f_part_product;
        for (std::ptrdiff_t j = m - 1; j >= 0; j--) {
            f_part_product.push_back(pow);
            pow *= f_[j*n + I_[setSize - 1][j]];
        }

        NthPower xj(x);
        for (std::size_t j = 0; j < m; j++) {
            Scalar fi_sum(uint64_t(0));
            for (std::size_t i = I_[setSize - 1][j] + 1; i < n; i++)
                fi_sum += f_[j*n + i];
            pow += fi_sum * xj.pow * f_part_product[m - j - 1];
            xj.go_next();
        }

        f_sum += pow;
        commit_scalars[commits.size() - 1] += pow * w3;

        // offsets
        points.emplace_back(offsets_S[t] + offsets_V[t] * bind_weight);
        scalars.emplace_back(f_sum * w3.negate());

        // (Gk), (Qk)
        NthPower x_k(x);
        for (std::size_t k = 0; k < m; k++) {
            points.emplace_back(proof.Gk_[k] + proof.Qk_[k] * bind_weight);
            scalars.emplace_back(x_k.pow.negate() * w3);
            x_k.go_next();
        }
    }

    // Add common generators
    points.emplace_back(g_);
    scalars.emplace_back(g_scalar);
    points.emplace_back(h_);
    scalars.emplace_back(h_scalar);
    for (std::size_t i = 0; i < m * n; i++) {
        points.emplace_back(h_gens[i]);
        scalars.emplace_back(h_scalars[i]);
    }
    for (std::size_t i = 0; i < commits.size(); i++) {
        points.emplace_back(commits[i]);
        scalars.emplace_back(commit_scalars[i]);
    }

    // Verify the batch
    secp_primitives::MultiExponent result(points, scalars);
    if (result.get_multiple().isInfinity()) {
        return true;
    }
    return false;
}

bool ParallelVerifier::membership_checks(const ParallelProof& proof) const {
    if (!(proof.A_.isMember() &&
         proof.B_.isMember() &&
         proof.C_.isMember() &&
         proof.D_.isMember()) ||
        (proof.A_.isInfinity() ||
         proof.B_.isInfinity() ||
         proof.C_.isInfinity() ||
         proof.D_.isInfinity()))
        return false;

    for (std::size_t i = 0; i < proof.f_.size(); i++)
    {
        if (!proof.f_[i].isMember() || proof.f_[i].isZero())
            return false;
    }
    const std::vector <GroupElement>& Gk = proof.Gk_;
    const std::vector <GroupElement>& Qk = proof.Qk_;
    for (std::size_t k = 0; k < m; ++k)
    {
        if (!(Gk[k].isMember() && Qk[k].isMember())
           || Gk[k].isInfinity() || Qk[k].isInfinity())
            return false;
    }
    if(!(proof.ZA_.isMember() &&
         proof.ZC_.isMember() &&
         proof.zV_.isMember() &&
         proof.zS_.isMember()) ||
        (proof.ZA_.isZero() ||
         proof.ZC_.isZero() ||
         proof.zV_.isZero() ||
         proof.zS_.isZero()))
        return false;
    return true;
}

bool ParallelVerifier::compute_fs(
        const ParallelProof& proof,
        const Scalar& x,
        std::vector<Scalar>& f_) const {
    for (std::size_t j = 0; j < proof.f_.size(); ++j) {
        if(proof.f_[j] == x)
            return false;
    }

    f_.reserve(n * m);
    for (std::size_t j = 0; j < m; ++j)
    {
        f_.push_back(Scalar(uint64_t(0)));
        Scalar temp;
        std::size_t k = n - 1;
        for (std::size_t i = 0; i < k; ++i)
        {
            temp += proof.f_[j * k + i];
            f_.emplace_back(proof.f_[j * k + i]);
        }
        f_[j * n] = x - temp;
    }
    return true;
}

void ParallelVerifier::compute_fis(int j, const std::vector<Scalar>& f, std::vector<Scalar>& f_i_) const {
    Scalar f_i(uint64_t(1));
    std::vector<Scalar>::iterator ptr = f_i_.begin();
    compute_fis(f_i, m, f, ptr, f_i_.end());
}

void ParallelVerifier::compute_fis(
        const Scalar& f_i,
        int j,
        const std::vector<Scalar>& f,
        std::vector<Scalar>::iterator& ptr,
        std::vector<Scalar>::iterator end_ptr) const {
    j--;
    if (j == -1)
    {
        if (ptr < end_ptr)
            *ptr++ += f_i;
        return;
    }

    Scalar t;

    for (std::size_t i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_fis(t, j, f, ptr, end_ptr);
    }
}

void ParallelVerifier::compute_batch_fis(
        Scalar& f_sum,
        const Scalar& f_i,
        int j,
        const std::vector<Scalar>& f,
        const Scalar& y,
        std::vector<Scalar>::iterator& ptr,
        std::vector<Scalar>::iterator start_ptr,
        std::vector<Scalar>::iterator end_ptr) const {
    j--;
    if (j == -1)
    {
        if(ptr >= start_ptr && ptr < end_ptr){
            *ptr++ += f_i * y;
            f_sum += f_i;
        }
        return;
    }

    Scalar t;

    for (std::size_t i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_batch_fis(f_sum, t, j, f, y, ptr, start_ptr, end_ptr);
    }
}

} //namespace lelantus