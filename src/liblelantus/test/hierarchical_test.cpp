#include "../hierarchical_prover.h"
#include "../hierarchical_verifier.h"

#include "lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <random>

namespace lelantus {

class HierarchicalTests : public LelantusTestingSetup {
public:
    HierarchicalTests() {}

public:
    void GenerateParams(uint64_t _N, uint64_t _n_T, uint64_t _m_T, uint64_t _n_M, uint64_t _m_M) {
        N = _N;
        n_T = _n_T;
        m_T = _m_T;
        n_M = _n_M;
        m_M = _m_M;
        if (!((uint64_t)pow(_n_T, _m_T) * (uint64_t)pow(_n_M, _m_M) == _N)) {
            throw std::invalid_argument("Invalid hierarchical proof parameters");
        }

        // For the one-of-many prover and verifier, we need to ensure the generator vectors begin with the commitment generators
        h_gens_T = RandomizeGroupElements(n_T * m_T);
        h_gens_M = RandomizeGroupElements(n_M * m_M);
        g.randomize();
        h1.randomize();
        h2.randomize();
        h_gens_T[1] = h1;
        h_gens_M[1] = h1;
        h_gens_T[0] = h2;
        h_gens_M[0] = h2;
    }

public:
    uint64_t N;
    uint64_t n_T;
    uint64_t m_T;
    uint64_t n_M;
    uint64_t m_M;

    std::vector<GroupElement> h_gens_T;
    std::vector<GroupElement> h_gens_M;
    GroupElement g, h1, h2;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_hierarchical_tests, HierarchicalTests)

BOOST_AUTO_TEST_CASE(generate_proofs)
{
    GenerateParams(32, 2, 3, 2, 2);

    auto commits = RandomizeGroupElements(N);
    HierarchicalProver prover(
        g, h1, h2, h_gens_T, h_gens_M,
        n_T, m_T,
        n_M, m_M
    );
    HierarchicalVerifier verifier(
        g, h1, h2, h_gens_T, h_gens_M,
        n_T, m_T,
        n_M, m_M
    );


    // For timing data
    std::default_random_engine randomizer;
    std::uniform_int_distribution<int> dist(0,N-1);
    const int trials = 1000;
    double prove_total = 0;
    double verify_total = 0;

    for (int i = 0; i < trials; i++) {
        Scalar v, r;
        v.randomize();
        r.randomize();

        int l = dist(randomizer);

        commits[l] = Primitives::double_commit(
            g, Scalar(uint64_t(0)),
            h1, v,
            h2, r
        );

        HierarchicalProof proof;

        // Prove
        auto start = std::chrono::steady_clock::now();
        prover.proof(
            commits,
            l,
            v,
            r,
            proof
        );
        auto stop = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::milli> duration_milliseconds = stop - start;
        prove_total += duration_milliseconds.count();

        // Verify
        start = std::chrono::steady_clock::now();
        verifier.verify(
            commits,
            proof
        );
        stop = std::chrono::steady_clock::now();
        duration_milliseconds = stop - start;
        verify_total += duration_milliseconds.count();
    }

    // Report the mean time
    printf("Mean proving time (%d trials): %f ms\n", trials, prove_total/trials);
    printf("Mean verification time (%d trials): %f ms\n", trials, verify_total/trials);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus