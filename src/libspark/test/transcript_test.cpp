#include "../transcript.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_transcript_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(init)
{
    // Identical domain separators
    Transcript transcript_1("Spam");
    Transcript transcript_2("Spam");
    BOOST_CHECK_EQUAL(transcript_1.challenge(), transcript_2.challenge());

    // Distinct domain separators
    transcript_1 = Transcript("Spam");
    transcript_2 = Transcript("Eggs");
    BOOST_CHECK_NE(transcript_1.challenge(), transcript_2.challenge());
}

BOOST_AUTO_TEST_CASE(add_types)
{
    // Add all fixed types and assert distinct challenges
    const std::string domain = "Spam";
    Transcript transcript(domain);

    Scalar scalar;
    scalar.randomize();
    transcript.add("Scalar", scalar);
    Scalar ch_1 = transcript.challenge();
    
    GroupElement group;
    group.randomize();
    transcript.add("Group", group);
    Scalar ch_2 = transcript.challenge();
    BOOST_CHECK_NE(ch_1, ch_2);

    std::vector<Scalar> scalars;
    for (std::size_t i = 0; i < 3; i++) {
        scalar.randomize();
        scalars.emplace_back(scalar);
    }
    Scalar ch_3 = transcript.challenge();
    BOOST_CHECK_NE(ch_2, ch_3);

    std::vector<GroupElement> groups;
    for (std::size_t i = 0; i < 3; i++) {
        group.randomize();
        groups.emplace_back(group);
    }
    Scalar ch_4 = transcript.challenge();
    BOOST_CHECK_NE(ch_3, ch_4);

    const std::string data = "Arbitrary string";
    const std::vector<unsigned char> data_char(data.begin(), data.end());
    transcript.add("Data", data_char);
    Scalar ch_5 = transcript.challenge();
    BOOST_CHECK_NE(ch_4, ch_5);
}

BOOST_AUTO_TEST_CASE(repeated_challenge)
{
    // Repeated challenges must be distinct
    Transcript transcript("Eggs");

    Scalar ch_1 = transcript.challenge();
    Scalar ch_2 = transcript.challenge();

    BOOST_CHECK_NE(ch_1, ch_2);
}

BOOST_AUTO_TEST_CASE(identical_transcripts)
{
    // Ensure that identical transcripts yield identical challenges
    Transcript prover("Beer");
    Transcript verifier("Beer");

    Scalar scalar;
    scalar.randomize();
    GroupElement group;
    group.randomize();

    prover.add("Scalar", scalar);
    verifier.add("Scalar", scalar);
    prover.add("Group", group);
    verifier.add("Group", group);

    BOOST_CHECK_EQUAL(prover.challenge(), verifier.challenge());
}

BOOST_AUTO_TEST_CASE(distinct_values)
{
    // Ensure that distinct transcript values yield distinct challenges
    Transcript prover("Soda");
    Transcript verifier("Soda");

    Scalar prover_scalar;
    prover_scalar.randomize();
    Scalar verifier_scalar;
    verifier_scalar.randomize();

    prover.add("Scalar", prover_scalar);
    verifier.add("Scalar", verifier_scalar);

    BOOST_CHECK_NE(prover.challenge(), verifier.challenge());
}

BOOST_AUTO_TEST_CASE(distinct_labels)
{
    // Ensure that distinct transcript labels yield distinct challenges
    Transcript prover("Soda");
    Transcript verifier("Soda");

    Scalar scalar;
    scalar.randomize();

    prover.add("Prover scalar", scalar);
    verifier.add("Verifier scalar", scalar);

    BOOST_CHECK_NE(prover.challenge(), verifier.challenge());
}

BOOST_AUTO_TEST_SUITE_END()

}