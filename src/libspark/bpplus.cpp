#include "bpplus.h"
#include "transcript.h"

namespace spark {

// Useful scalar constants
const Scalar ZERO = Scalar((uint64_t) 0);
const Scalar ONE = Scalar((uint64_t) 1);
const Scalar TWO = Scalar((uint64_t) 2);
    
BPPlus::BPPlus(
        const GroupElement& G_,
        const GroupElement& H_,
        const std::vector<GroupElement>& Gi_,
        const std::vector<GroupElement>& Hi_,
        const std::size_t N_)
        : G (G_)
        , H (H_)
        , Gi (Gi_)
        , Hi (Hi_)
        , N (N_)
{
    if (Gi.size() != Hi.size()) {
        throw std::invalid_argument("Bad BPPlus generator sizes!");
    }

    // Bit length must be a power of two
    if ((N & (N - 1) != 0)) {
        throw std::invalid_argument("Bad BPPlus bit length!");
    }

    // Compute 2**N-1 for optimized verification
    TWO_N_MINUS_ONE = TWO;
    for (int i = 0; i < log2(N); i++) {
        TWO_N_MINUS_ONE *= TWO_N_MINUS_ONE;
    }
    TWO_N_MINUS_ONE -= ONE;
}

static inline std::size_t log2(std::size_t n) {
    std::size_t l = 0;
    while ((n >>= 1) != 0) {
        l++;
    }
    
    return l;
}

void BPPlus::prove(
        const std::vector<Scalar>& v,
        const std::vector<Scalar>& r,
        const std::vector<GroupElement>& C,  
        BPPlusProof& proof) {
    // Check statement validity
    std::size_t M = C.size();
    if (N*M > Gi.size()) {
        throw std::invalid_argument("Bad BPPlus statement!");   
    }
    if (!(v.size() == M && r.size() == M)) {
        throw std::invalid_argument("Bad BPPlus statement!");
    }
    for (std::size_t j = 0; j < M; j++) {
        if (!(H*v[j] + G*r[j] == C[j])) {
            throw std::invalid_argument("Bad BPPlus statement!");
        }
    }

    // Set up transcript
    Transcript transcript("SPARK_BPPLUS");
    transcript.add("G", G);
    transcript.add("H", H);
    transcript.add("Gi", Gi);
    transcript.add("Hi", Hi);
    transcript.add("N", Scalar(N));
    transcript.add("C", C);

    // Decompose bits
    std::vector<std::vector<bool>> bits;
    bits.resize(M);
    for (std::size_t j = 0; j < M; j++) {
        v[j].get_bits(bits[j]);
    }

    // Compute aL, aR
    std::vector<Scalar> aL, aR;
    aL.reserve(N*M);
    aR.reserve(N*M);
    for (std::size_t j = 0; j < M; ++j)
    {
        for (std::size_t i = 1; i <= N; ++i)
        {
            aL.emplace_back(uint64_t(bits[j][bits[j].size() - i]));
            aR.emplace_back(Scalar(uint64_t(bits[j][bits[j].size() - i])) - ONE);
        }
    }

    // Compute A
    Scalar alpha;
    alpha.randomize();
    proof.A = G*alpha;
    for (std::size_t i = 0; i < N*M; i++) {
        proof.A += Gi[i]*aL[i] + Hi[i]*aR[i];
    }
    transcript.add("A", proof.A);

    // Challenges
    Scalar y = transcript.challenge();
    Scalar z = transcript.challenge();

    // Challenge powers
    std::vector<Scalar> y_powers;
    y_powers.resize(M*N + 2);
    y_powers[0] = ZERO;
    y_powers[1] = y;
    for (std::size_t i = 2; i < M*N + 2; i++) {
        y_powers[i] = y_powers[i-1]*y;
    }

    // Compute d
    std::vector<Scalar> d;
    d.resize(M*N);
    d[0] = z.square();
    for (std::size_t i = 1; i < N; i++) {
        d[i] = TWO*d[i-1];
    }
    for (std::size_t j = 1; j < M; j++) {
        for (std::size_t i = 0; i < N; i++) {
            d[j*N+i] = d[(j-1)*N+i]*z.square();
        }
    }

    // Compute aL1, aR1
    std::vector<Scalar> aL1, aR1;
    for (std::size_t i = 0; i < N*M; i++) {
        aL1.emplace_back(aL[i] - z);
        aR1.emplace_back(aR[i] + d[i]*y_powers[N*M - i] + z);
    }

    // Compute alpha1
    Scalar alpha1 = alpha;
    Scalar z_even_powers = 1;
    for (std::size_t j = 0; j < M; j++) {
        z_even_powers *= z.square();
        alpha1 += z_even_powers*r[j]*y_powers[N*M+1];
    }

    // Run the inner product rounds
    std::vector<GroupElement> Gi1(Gi);
    std::vector<GroupElement> Hi1(Hi);
    std::vector<Scalar> a1(aL1);
    std::vector<Scalar> b1(aR1);
    std::size_t N1 = N*M;

    while (N1 > 1) {
        N1 /= 2;

        Scalar dL, dR;
        dL.randomize();
        dR.randomize();

        // Compute cL, cR
        Scalar cL, cR;
        for (std::size_t i = 0; i < N1; i++) {
            cL += a1[i]*y_powers[i+1]*b1[i+N1];
            cR += a1[i+N1]*y_powers[N1]*y_powers[i+1]*b1[i];
        }

        // Compute L, R
        GroupElement L_, R_;
        Scalar y_N1_inverse = y_powers[N1].inverse();
        for (std::size_t i = 0; i < N1; i++) {
            L_ += Gi1[i+N1]*(a1[i]*y_N1_inverse) + Hi1[i]*b1[i+N1];
            R_ += Gi1[i]*(a1[i+N1]*y_powers[N1]) + Hi1[i+N1]*b1[i];
        }
        L_ += H*cL + G*dL;
        R_ += H*cR + G*dR;
        proof.L.emplace_back(L_);
        proof.R.emplace_back(R_);

        transcript.add("L", L_);
        transcript.add("R", R_);
        Scalar e = transcript.challenge();
        Scalar e_inverse = e.inverse();

        // Compress round elements
        for (std::size_t i = 0; i < N1; i++) {
            Gi1[i] = Gi1[i]*e_inverse + Gi1[i+N1]*(e*y_N1_inverse);
            Hi1[i] = Hi1[i]*e + Hi1[i+N1]*e_inverse;
            a1[i] = a1[i]*e + a1[i+N1]*y_powers[N1]*e_inverse;
            b1[i] = b1[i]*e_inverse + b1[i+N1]*e;
        }
        Gi1.resize(N1);
        Hi1.resize(N1);
        a1.resize(N1);
        b1.resize(N1);

        // Update alpha1
        alpha1 = dL*e.square() + alpha1 + dR*e_inverse.square();
    }

    // Final proof elements
    Scalar r_, s_, d_, eta_;
    r_.randomize();
    s_.randomize();
    d_.randomize();
    eta_.randomize();

    proof.A1 = Gi1[0]*r_ + Hi1[0]*s_ + H*(r_*y*b1[0] + s_*y*a1[0]) + G*d_;
    proof.B = H*(r_*y*s_) + G*eta_;

    transcript.add("A1", proof.A1);
    transcript.add("B", proof.B);
    Scalar e1 = transcript.challenge();

    proof.r1 = r_ + a1[0]*e1;
    proof.s1 = s_ + b1[0]*e1;
    proof.d1 = eta_ + d_*e1 + alpha1*e1.square();
}

bool BPPlus::verify(const std::vector<GroupElement>& C, const BPPlusProof& proof) {
    std::vector<std::vector<GroupElement>> C_batch = {C};
    std::vector<BPPlusProof> proof_batch = {proof};

    return verify(C_batch, proof_batch);
}

bool BPPlus::verify(const std::vector<std::vector<GroupElement>>& C, const std::vector<BPPlusProof>& proofs) {
    // Preprocess all proofs
    if (!(C.size() == proofs.size())) {
        return false;
    }
    std::size_t N_proofs = proofs.size();
    std::size_t max_M = 0; // maximum number of aggregated values across all proofs

    // Check aggregated input consistency
    for (std::size_t k = 0; k < N_proofs; k++) {
        std::size_t M = C[k].size();

        // Require a power of two
        if (M == 0) {
            return false;
        }
        if ((M & (M - 1)) != 0) {
            return false;
        }

        // Track the maximum value
        if (M > max_M) {
            max_M = M;
        }

        // Check inner produce round consistency
        std::size_t rounds = proofs[k].L.size();
        if (proofs[k].R.size() != rounds) {
            return false;
        }
        if (log2(N*M) != rounds) {
            return false;
        }
    }

    // Check the bounds on the batch
    if (max_M*N > Gi.size() || max_M*N > Hi.size()) {
        return false;
    }

    // Set up final multiscalar multiplication and common scalars
    std::vector<GroupElement> points;
    std::vector<Scalar> scalars;
    Scalar G_scalar, H_scalar;

    // Interleave the Gi and Hi scalars
    for (std::size_t i = 0; i < max_M*N; i++) {
        points.emplace_back(Gi[i]);
        scalars.emplace_back(ZERO);
        points.emplace_back(Hi[i]);
        scalars.emplace_back(ZERO);
    }

    // Process each proof and add to the batch
    for (std::size_t k_proofs = 0; k_proofs < N_proofs; k_proofs++) {
        const BPPlusProof proof = proofs[k_proofs];
        const std::size_t M = C[k_proofs].size();
        const std::size_t rounds = proof.L.size();

        // Weight this proof in the batch
        Scalar w = ZERO;
        while (w == ZERO) {
            w.randomize();
        }

        // Set up transcript
        Transcript transcript("SPARK_BPPLUS");
        transcript.add("G", G);
        transcript.add("H", H);
        transcript.add("Gi", Gi);
        transcript.add("Hi", Hi);
        transcript.add("N", Scalar(N));
        transcript.add("C", C[k_proofs]);
        transcript.add("A", proof.A);

        // Get challenges
        Scalar y = transcript.challenge();
        Scalar y_inverse = y.inverse();
        Scalar y_NM = y;
        for (std::size_t i = 0; i < rounds; i++) {
            y_NM = y_NM.square();
        }
        Scalar y_NM_1 = y_NM*y;

        Scalar z = transcript.challenge();

        std::vector<Scalar> e;
        std::vector<Scalar> e_inverse;
        for (std::size_t j = 0; j < rounds; j++) {
            transcript.add("L", proof.L[j]);
            transcript.add("R", proof.R[j]);
            e.emplace_back(transcript.challenge());
            e_inverse.emplace_back(e[j].inverse());
        }

        transcript.add("A1", proof.A1);
        transcript.add("B", proof.B);
        Scalar e1 = transcript.challenge();

        // C_j: -e1**2 * z**(2*(j + 1)) * y**(N*M + 1) * w
        Scalar C_scalar = e1.square().negate()*z.square()*y_NM_1*w;
        for (std::size_t j = 0; j < M; j++) {
            points.emplace_back(C[k_proofs][j]);
            scalars.emplace_back(C_scalar);

            C_scalar *= z.square();
        }

        // B: -w
        points.emplace_back(proof.B);
        scalars.emplace_back(w.negate());

        // A1: -w*e1
        points.emplace_back(proof.A1);
        scalars.emplace_back(w.negate()*e1);

        // A: -w*e1**2
        points.emplace_back(proof.A);
        scalars.emplace_back(w.negate()*e1.square());

        // G: w*d1
        G_scalar += w*proof.d1;

        // Compute d
        std::vector<Scalar> d;
        d.resize(N*M);
        d[0] = z.square();
        for (std::size_t i = 1; i < N; i++) {
            d[i] = d[i-1] + d[i-1];
        }
        for (std::size_t j = 1; j < M; j++) {
            for (std::size_t i = 0; i < N; i++) {
                d[j*N + i] = d[(j - 1)*N + i]*z.square();
            }
        }

        // Sum the elements of d
        Scalar sum_d = z.square();
        Scalar temp_z = sum_d;
        std::size_t temp_2M = 2*M;
        while (temp_2M > 2) {
            sum_d += sum_d*temp_z;
            temp_z = temp_z.square();
            temp_2M /= 2;
        }
        sum_d *= TWO_N_MINUS_ONE;

        // Sum the powers of y
        Scalar sum_y;
        Scalar track = y;
        for (std::size_t i = 0; i < N*M; i++) {
            sum_y += track;
            track *= y;
        }

        // H: w*(r1*y*s1 + e1**2*(y**(N*M + 1)*z*sum_d + (z**2-z)*sum_y))
        H_scalar += w*(proof.r1*y*proof.s1 + e1.square()*(y_NM_1*z*sum_d + (z.square() - z)*sum_y));

        // Track some iterated exponential terms
        Scalar iter_y_inv = ONE; // y.inverse()**i
        Scalar iter_y_NM = y_NM; // y**(N*M - i)

        // Gi, Hi
        for (std::size_t i = 0; i < N*M; i++) {
            Scalar g = proof.r1*e1*iter_y_inv;
            Scalar h = proof.s1*e1;
            for (std::size_t j = 0; j < rounds; j++) {
                if ((i >> j) & 1) {
                    g *= e[rounds-j-1];
                    h *= e_inverse[rounds-j-1];
                } else {
                    h *= e[rounds-j-1];
                    g *= e_inverse[rounds-j-1];
                }
            }

            // Gi
            scalars[2*i] += w*(g + e1.square()*z);
            
            // Hi
            scalars[2*i+1] += w*(h - e1.square()*(d[i]*iter_y_NM+z));

            // Update the iterated values
            iter_y_inv *= y_inverse;
            iter_y_NM *= y_inverse;
        }

        // L, R
        for (std::size_t j = 0; j < rounds; j++) {
            points.emplace_back(proof.L[j]);
            scalars.emplace_back(w*(e1.square().negate()*e[j].square()));
            points.emplace_back(proof.R[j]);
            scalars.emplace_back(w*(e1.square().negate()*e_inverse[j].square()));
        }
    }

    // Add the common generators
    points.emplace_back(G);
    scalars.emplace_back(G_scalar);
    points.emplace_back(H);
    scalars.emplace_back(H_scalar);

    // Test the batch
    secp_primitives::MultiExponent multiexp(points, scalars);
    return multiexp.get_multiple().isInfinity();
}

}