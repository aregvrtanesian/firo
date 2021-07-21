#include "../parallel_prover.h"
#include "../parallel_verifier.h"

#include "lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

class ParallelTests : public LelantusTestingSetup {
public:
    struct Secret {
    public:
        Secret(std::size_t l) : l(l) {
            s.randomize();
            v.randomize();
            r.randomize();
        }

    public:
        std::size_t l;
        Scalar s, v, r;
    };

public:
    typedef ParallelProver Prover;
    typedef ParallelProof Proof;
    typedef ParallelVerifier Verifier;

public:
    ParallelTests() {}

public:
    void GenerateParams(std::size_t _N, std::size_t _n, std::size_t _m = 0) {
        N = _N;
        n = _n;
        m = _m;
        if (!m) {
            if (n <= 1) {
                throw std::logic_error("Try to get value of m from invalid n");
            }

            m = (std::size_t)std::round(log(N) / log(n));
        }

        h_gens = RandomizeGroupElements(n * m);
        g.randomize();
        h.randomize();
    }

    void GenerateBatchProof(
        Prover &prover,
        std::vector<GroupElement> const &coins_S,
        std::vector<GroupElement> const &coins_V,
        std::size_t l,
        Scalar const &s,
        Scalar const &v,
        Scalar const &r,
        Scalar const &x,
        Proof &proof
    ) {
        auto gs = g * s.negate();
        std::vector<GroupElement> commits_S(coins_S.begin(), coins_S.end());
        std::vector<GroupElement> commits_V(coins_V.begin(), coins_V.end());
        for (auto &c : commits_S) {
            c += gs;
        }

        Scalar rA, rB, rC, rD;
        rA.randomize();
        rB.randomize();
        rC.randomize();
        rD.randomize();

        std::vector<Scalar> sigma;
        std::vector<Scalar> Sk, Vk;
        Sk.resize(m);
        Vk.resize(m);

        std::vector<Scalar> a;
        a.resize(n * m);

        prover.parallel_commit(
            commits_S, commits_V, l, rA, rB, rC, rD, a, Sk, Vk, sigma, proof);

        prover.parallel_response(
            sigma, a, rA, rB, rC, rD, v, r, Sk, Vk, x, proof);
    }

public:
    std::size_t N;
    std::size_t n;
    std::size_t m;

    std::vector<GroupElement> h_gens;
    GroupElement g;
    GroupElement h;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_parallel_tests, ParallelTests)

BOOST_AUTO_TEST_CASE(one_out_of_N_variable_batch)
{
    GenerateParams(64, 4);

    std::size_t commit_size = 60; // require padding
    auto commits_S = RandomizeGroupElements(commit_size);
    auto commits_V = RandomizeGroupElements(commit_size);

    // Generate
    std::vector<Secret> secrets;
    std::vector<std::size_t> indexes = { 0, 1, 3, 59 };
    std::vector<std::size_t> set_sizes = { 60, 60, 59, 16 };
    
    for (auto index : indexes) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits_S[index] = g * s.s + h * s.r;
        commits_V[index] = h * s.v;
    }

    Prover prover(g, h, h_gens, n, m);
    Verifier verifier(g, h, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;
    std::vector<Scalar> challenges;

    for (std::size_t i = 0; i < indexes.size(); i++) {
        Scalar x;
        x.randomize();
        proofs.emplace_back();
        serials.push_back(secrets[i].s);
        std::vector<GroupElement> commits_S_(commits_S.begin() + commit_size - set_sizes[i], commits_S.end());
        std::vector<GroupElement> commits_V_(commits_V.begin() + commit_size - set_sizes[i], commits_V.end());
        GenerateBatchProof(
            prover,
            commits_S_,
            commits_V_,
            secrets[i].l - (commit_size - set_sizes[i]),
            secrets[i].s,
            secrets[i].v,
            secrets[i].r,
            x,
            proofs.back()
        );
        challenges.emplace_back(x);

        // Verify individual proofs as a sanity check
        BOOST_CHECK(verifier.singleverify(commits_S, commits_V, x, secrets[i].s, set_sizes[i], proofs.back()));
        BOOST_CHECK(verifier.singleverify(commits_S_, commits_V_, x, secrets[i].s, proofs.back()));
    }

    BOOST_CHECK(verifier.batchverify(commits_S, commits_V, challenges, serials, set_sizes, proofs));
}

BOOST_AUTO_TEST_CASE(one_out_of_N_batch)
{
    GenerateParams(16, 4);

    auto commits_S = RandomizeGroupElements(N);
    auto commits_V = RandomizeGroupElements(N);

    // Generate
    std::vector<Secret> secrets;

    for (auto index : {1, 3, 5, 9, 15}) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits_S[index] = g * s.s + h * s.r;
        commits_V[index] = h * s.v;
    }

    Prover prover(g, h, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;

    Scalar x;
    x.randomize();

    for (auto const &s : secrets) {
        proofs.emplace_back();
        serials.push_back(s.s);
        GenerateBatchProof(
            prover, commits_S, commits_V, s.l, s.s, s.v, s.r, x, proofs.back());
    }

    Verifier verifier(g, h, h_gens, n, m);
    BOOST_CHECK(verifier.batchverify(commits_S, commits_V, x, serials, proofs));

    // verify subset of valid proofs should success also
    serials.pop_back();
    proofs.pop_back();
    BOOST_CHECK(verifier.batchverify(commits_S, commits_V, x, serials, proofs));
}

BOOST_AUTO_TEST_CASE(one_out_of_N_batch_with_some_invalid_proof)
{
    GenerateParams(16, 4);

    auto commits_S = RandomizeGroupElements(N);
    auto commits_V = RandomizeGroupElements(N);

    // Generate
    std::vector<Secret> secrets;

    for (auto index : {1, 3}) {
        secrets.emplace_back(index);

        auto &s = secrets.back();

        commits_S[index] = g * s.s + h * s.r;
        commits_V[index] = h * s.v;
    }

    Prover prover(g, h, h_gens, n, m);
    std::vector<Proof> proofs;
    std::vector<Scalar> serials;

    Scalar x;
    x.randomize();

    for (auto const &s : secrets) {
        proofs.emplace_back();
        serials.push_back(s.s);
        GenerateBatchProof(
            prover, commits_S, commits_V, s.l, s.s, s.v, s.r, x, proofs.back());
    }

    // Add an invalid
    proofs.push_back(proofs.back());

    serials.emplace_back(serials.back());
    serials.back().randomize();

    Verifier verifier(g, h, h_gens, n, m);
    BOOST_CHECK(!verifier.batchverify(commits_S, commits_V, x, serials, proofs));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus