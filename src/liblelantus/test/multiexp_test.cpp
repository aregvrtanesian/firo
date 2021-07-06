#include "../sigmaextended_prover.h"
#include "../sigmaextended_verifier.h"

#include "lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>

#include <chrono>

namespace lelantus {

class MultiexpTests : public LelantusTestingSetup {
public:
    MultiexpTests() {}
};

BOOST_FIXTURE_TEST_SUITE(multiexp_tests, MultiexpTests)

BOOST_AUTO_TEST_CASE(weights)
{
    const std::size_t n = 64000;
    const std::size_t c = 1024;

    // Prepare inputs
    std::vector<GroupElement> A = RandomizeGroupElements(n);
    std::vector<GroupElement> B = RandomizeGroupElements(n);
    std::vector<GroupElement> C;
    C.reserve(n);
    std::vector<Scalar> s;
    s.reserve(n);
    s.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        s[i].randomize();
    }

    // Perform a pre-weighting first
    auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < n; i++) {
        C.emplace_back(A[i] + B[i]*c);
    }
    secp_primitives::MultiExponent mult_left(C, s);
    GroupElement left = mult_left.get_multiple();
    auto stop = std::chrono::steady_clock::now();
    long millis = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();
    printf("Pre-weighting time (ms): %ld\n", millis);

    // Do not perform a pre-weighting
    std::vector<GroupElement> A_long;
    A_long.reserve(2*n);
    std::vector<Scalar> s_long;
    s_long.reserve(2*n);
    
    start = std::chrono::steady_clock::now();
    A_long.insert(A_long.end(), A.begin(), A.end());
    A_long.insert(A_long.end(), B.begin(), B.end());
    s_long.insert(s_long.end(), s.begin(), s.end());
    s_long.insert(s_long.end(), s.begin(), s.end());
    for (std::size_t i = n; i < 2*n; i++) {
        s_long[i] *= c;
    }
    secp_primitives::MultiExponent mult_right(C, s);
    GroupElement right = mult_right.get_multiple();
    stop = std::chrono::steady_clock::now();
    millis = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();
    printf("Post-weighting time (ms): %ld\n", millis);

    // Sanity check that the results match
    BOOST_CHECK(left == right);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus