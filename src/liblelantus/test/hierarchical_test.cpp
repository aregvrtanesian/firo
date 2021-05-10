#include "../hierarchical_prover.h"
#include "../hierarchical_verifier.h"

#include "lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>

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
        if (!((uint64_t)pow(_n_T, _m_T) * (uint64_t)pow(_n_M, _m_M))) {
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


    for (auto l : {0, 1, 3, 5, 9, 31}) {
        Scalar v, r;
        v.randomize();
        r.randomize();

        commits[l] = Primitives::double_commit(
            g, Scalar(uint64_t(0)),
            h1, v,
            h2, r
        );

        HierarchicalProof proof;
        prover.proof(
            commits,
            l,
            v,
            r,
            proof
        );
        verifier.verify(
            commits,
            proof
        );
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus