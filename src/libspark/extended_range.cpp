#include "extended_range.h"

namespace spark {

// Useful scalar constants
const Scalar ZERO = Scalar((uint64_t) 0);
const Scalar ONE = Scalar((uint64_t) 1);
const Scalar TWO = Scalar((uint64_t) 2);
    
ExtendedRange::ExtendedRange(
        const GroupElement& F_,
        const GroupElement& G_,
        const GroupElement& H_,
        const std::vector<GroupElement>& Gi_,
        const std::vector<GroupElement>& Hi_,
        const std::size_t N_)
        : F (F_)
        , G (G_)
        , H (H_)
        , Gi (Gi_)
        , Hi (Hi_)
        , N (N_)
{
    if (Gi.size() != Hi.size()) {
        throw std::invalid_argument("Bad extended range generator sizes!");
    }

    // Bit length must be a power of two
    if ((N & (N - 1) != 0)) {
        throw std::invalid_argument("Bad extended range bit length!");
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

void ExtendedRange::prove(
        const std::vector<Scalar>& a,
        const std::vector<Scalar>& v,
        const std::vector<Scalar>& r,
        const std::vector<GroupElement>& C,  
        ExtendedRangeProof& proof) {
    // Check statement validity
    std::size_t M = C.size();
    if (N*M > Gi.size()) {
        throw std::invalid_argument("Bad extended range statement!");   
    }
    if (!(v.size() == M && r.size() == M)) {
        throw std::invalid_argument("Bad extended range statement!");
    }
    for (std::size_t j = 0; j < M; j++) {
        if (!(F*a[j] + G*v[j] + H*r[j] == C[j])) {
            throw std::invalid_argument("Bad extended range statement!");
        }
    }

    // Set up transcript
    Transcript transcript(LABEL_TRANSCRIPT_EXTENDED_RANGE_PROOF);
    transcript.add("F", F);
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
            aL.emplace_back(Scalar(uint64_t(bits[j][bits[j].size() - i])));
            aR.emplace_back(Scalar(uint64_t(bits[j][bits[j].size() - i])) - ONE);
        }
    }

    // Compute A
    Scalar alpha;
    Scalar alpha_;
    alpha.randomize();
    alpha_.randomize();

    std::vector<GroupElement> A_points;
    std::vector<Scalar> A_scalars;
    A_points.reserve(2*N*M + 1);
    A_points.reserve(2*N*M + 1);

    A_points.emplace_back(F);
    A_scalars.emplace_back(alpha_);
    A_points.emplace_back(H);
    A_scalars.emplace_back(alpha);
    for (std::size_t i = 0; i < N*M; i++) {
        A_points.emplace_back(Gi[i]);
        A_scalars.emplace_back(aL[i]);
        A_points.emplace_back(Hi[i]);
        A_scalars.emplace_back(aR[i]);
    }
    secp_primitives::MultiExponent A_multiexp(A_points, A_scalars);
    proof.A = A_multiexp.get_multiple();
    transcript.add("A", proof.A);

    // Challenges
    Scalar y = transcript.challenge("y");
    Scalar z = transcript.challenge("z");
    Scalar z_square = z.square();

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
    d[0] = z_square;
    for (std::size_t i = 1; i < N; i++) {
        d[i] = TWO*d[i-1];
    }
    for (std::size_t j = 1; j < M; j++) {
        for (std::size_t i = 0; i < N; i++) {
            d[j*N+i] = d[(j-1)*N+i]*z_square;
        }
    }

    // Compute aL_hat, aR_hat
    std::vector<Scalar> aL_hat, aR_hat;
    for (std::size_t i = 0; i < N*M; i++) {
        aL_hat.emplace_back(aL[i] - z);
        aR_hat.emplace_back(aR[i] + d[i]*y_powers[N*M - i] + z);
    }

    // Compute alpha_hat, alpha_hat_
    Scalar alpha_hat = alpha;
    Scalar alpha_hat_ = alpha_;
    Scalar z_even_powers = 1;
    for (std::size_t j = 0; j < M; j++) {
        z_even_powers *= z_square;
        alpha_hat += z_even_powers*r[j]*y_powers[N*M+1];
        alpha_hat_ += z_even_powers*a[j]*y_powers[N*M+1];
    }

    // Run the inner product rounds
    std::vector<GroupElement> ip_Gi(Gi);
    std::vector<GroupElement> ip_Hi(Hi);
    std::vector<Scalar> ip_a(aL_hat);
    std::vector<Scalar> ip_b(aR_hat);
    Scalar ip_alpha(alpha_hat);
    Scalar ip_alpha_(alpha_hat_);
    std::size_t ip_N = N*M;

    while (ip_N > 1) {
        ip_N /= 2;

        Scalar dL, dR;
        Scalar dL_, dR_;
        dL.randomize();
        dR.randomize();
        dL_.randomize();
        dR_.randomize();

        // Compute cL, cR
        Scalar cL, cR;
        for (std::size_t i = 0; i < ip_N; i++) {
            cL += ip_a[i]*y_powers[i+1]*ip_b[i+ip_N];
            cR += ip_a[i+ip_N]*y_powers[ip_N]*y_powers[i+1]*ip_b[i];
        }

        // Compute L, R
        GroupElement ip_L, ip_R;
        std::vector<GroupElement> L_points, R_points;
        std::vector<Scalar> L_scalars, R_scalars;
        L_points.reserve(2*ip_N + 3);
        R_points.reserve(2*ip_N + 3);
        L_scalars.reserve(2*ip_N + 3);
        R_scalars.reserve(2*ip_N + 3);
        Scalar y_ip_N_inverse = y_powers[ip_N].inverse();
        for (std::size_t i = 0; i < ip_N; i++) {
            L_points.emplace_back(ip_Gi[i+ip_N]);
            L_scalars.emplace_back(ip_a[i]*y_ip_N_inverse);
            L_points.emplace_back(ip_Hi[i]);
            L_scalars.emplace_back(ip_b[i+ip_N]);

            R_points.emplace_back(ip_Gi[i]);
            R_scalars.emplace_back(ip_a[i+ip_N]*y_powers[ip_N]);
            R_points.emplace_back(ip_Hi[i+ip_N]);
            R_scalars.emplace_back(ip_b[i]);
        }
        L_points.emplace_back(F);
        L_scalars.emplace_back(dL_);
        L_points.emplace_back(G);
        L_scalars.emplace_back(cL);
        L_points.emplace_back(H);
        L_scalars.emplace_back(dL);
        R_points.emplace_back(F);
        R_scalars.emplace_back(dR_);
        R_points.emplace_back(G);
        R_scalars.emplace_back(cR);
        R_points.emplace_back(H);
        R_scalars.emplace_back(dR);

        secp_primitives::MultiExponent L_multiexp(L_points, L_scalars);
        secp_primitives::MultiExponent R_multiexp(R_points, R_scalars);
        ip_L = L_multiexp.get_multiple();
        ip_R = R_multiexp.get_multiple();
        proof.ip_L.emplace_back(ip_L);
        proof.ip_R.emplace_back(ip_R);

        transcript.add("ip_L", ip_L);
        transcript.add("ip_R", ip_R);
        Scalar e = transcript.challenge("e");
        Scalar e_inverse = e.inverse();

        // Update round elements
        for (std::size_t i = 0; i < ip_N; i++) {
            ip_Gi[i] = ip_Gi[i]*e_inverse + ip_Gi[i+ip_N]*(e*y_ip_N_inverse);
            ip_Hi[i] = ip_Hi[i]*e + ip_Hi[i+ip_N]*e_inverse;
            ip_a[i] = ip_a[i]*e + ip_a[i+ip_N]*y_powers[ip_N]*e_inverse;
            ip_b[i] = ip_b[i]*e_inverse + ip_b[i+ip_N]*e;
        }
        ip_Gi.resize(ip_N);
        ip_Hi.resize(ip_N);
        ip_a.resize(ip_N);
        ip_b.resize(ip_N);

        ip_alpha = dL*e.square() + ip_alpha + dR*e_inverse.square();
        ip_alpha_ = dL_*e.square() + ip_alpha_ + dR_*e_inverse.square();
    }

    // Final proof elements
    Scalar ip_r, ip_s, ip_delta, ip_eta, ip_delta_, ip_eta_;
    ip_r.randomize();
    ip_s.randomize();
    ip_delta.randomize();
    ip_eta.randomize();
    ip_delta_.randomize();
    ip_eta_.randomize();

    proof.ip_A = ip_Gi[0]*ip_r + ip_Hi[0]*ip_s + F*ip_delta_ + G*(ip_r*y*ip_b[0] + ip_s*y*ip_a[0]) + H*ip_delta;
    proof.ip_B = F*ip_eta_ + G*(ip_r*y*ip_s) + H*ip_eta;

    transcript.add("ip_A", proof.ip_A);
    transcript.add("ip_B", proof.ip_B);
    Scalar e1 = transcript.challenge("e1");

    proof.ip_r1 = ip_r + ip_a[0]*e1;
    proof.ip_s1 = ip_s + ip_b[0]*e1;
    proof.ip_delta1 = ip_eta + ip_delta*e1 + ip_alpha*e1.square();
    proof.ip_delta1_ = ip_eta_ + ip_delta_*e1 + ip_alpha_*e1.square();
}

bool ExtendedRange::verify(const std::vector<GroupElement>& C, const ExtendedRangeProof& proof) {
    std::vector<std::vector<GroupElement>> C_batch = {C};
    std::vector<ExtendedRangeProof> proof_batch = {proof};

    return verify(C_batch, proof_batch);
}

bool ExtendedRange::verify(const std::vector<std::vector<GroupElement>>& C, const std::vector<ExtendedRangeProof>& proofs) {
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
        std::size_t rounds = proofs[k].ip_L.size();
        if (proofs[k].ip_R.size() != rounds) {
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
    Scalar F_scalar, G_scalar, H_scalar;

    // Interleave the Gi and Hi scalars
    for (std::size_t i = 0; i < max_M*N; i++) {
        points.emplace_back(Gi[i]);
        scalars.emplace_back(ZERO);
        points.emplace_back(Hi[i]);
        scalars.emplace_back(ZERO);
    }

    // Process each proof and add to the batch
    for (std::size_t k_proofs = 0; k_proofs < N_proofs; k_proofs++) {
        const ExtendedRangeProof proof = proofs[k_proofs];
        const std::size_t M = C[k_proofs].size();
        const std::size_t rounds = proof.ip_L.size();

        // Weight this proof in the batch
        Scalar w = ZERO;
        while (w == ZERO) {
            w.randomize();
        }

        // Set up transcript
        Transcript transcript(LABEL_TRANSCRIPT_EXTENDED_RANGE_PROOF);
        transcript.add("F", F);
        transcript.add("G", G);
        transcript.add("H", H);
        transcript.add("Gi", Gi);
        transcript.add("Hi", Hi);
        transcript.add("N", Scalar(N));
        transcript.add("C", C[k_proofs]);
        transcript.add("A", proof.A);

        // Get challenges
        Scalar y = transcript.challenge("y");
        Scalar y_inverse = y.inverse();
        Scalar y_NM = y;
        for (std::size_t i = 0; i < rounds; i++) {
            y_NM = y_NM.square();
        }
        Scalar y_NM_1 = y_NM*y;

        Scalar z = transcript.challenge("z");
        Scalar z_square = z.square();

        std::vector<Scalar> e;
        std::vector<Scalar> e_inverse;
        for (std::size_t j = 0; j < rounds; j++) {
            transcript.add("ip_L", proof.ip_L[j]);
            transcript.add("ip_R", proof.ip_R[j]);
            e.emplace_back(transcript.challenge("e"));
            e_inverse.emplace_back(e[j].inverse());
        }

        transcript.add("ip_A", proof.ip_A);
        transcript.add("ip_B", proof.ip_B);
        Scalar e1 = transcript.challenge("e1");
        Scalar e1_square = e1.square();

        // C_j: -e1**2 * z**(2*(j + 1)) * y**(N*M + 1) * w
        Scalar C_scalar = e1_square.negate()*z_square*y_NM_1*w;
        for (std::size_t j = 0; j < M; j++) {
            points.emplace_back(C[k_proofs][j]);
            scalars.emplace_back(C_scalar);

            C_scalar *= z.square();
        }

        // ip_B: -w
        points.emplace_back(proof.ip_B);
        scalars.emplace_back(w.negate());

        // ip_A: -w*e1
        points.emplace_back(proof.ip_A);
        scalars.emplace_back(w.negate()*e1);

        // A: -w*e1**2
        points.emplace_back(proof.A);
        scalars.emplace_back(w.negate()*e1_square);

        // F: w*d1_
        F_scalar += w*proof.ip_delta1_;

        // H: w*d1
        H_scalar += w*proof.ip_delta1;

        // Compute d
        std::vector<Scalar> d;
        d.resize(N*M);
        d[0] = z_square;
        for (std::size_t i = 1; i < N; i++) {
            d[i] = d[i-1] + d[i-1];
        }
        for (std::size_t j = 1; j < M; j++) {
            for (std::size_t i = 0; i < N; i++) {
                d[j*N + i] = d[(j - 1)*N + i]*z_square;
            }
        }

        // Sum the elements of d
        Scalar sum_d = z_square;
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

        // G: w*(r1*y*s1 + e1**2*(y**(N*M + 1)*z*sum_d + (z**2-z)*sum_y))
        G_scalar += w*(proof.ip_r1*y*proof.ip_s1 + e1_square*(y_NM_1*z*sum_d + (z_square - z)*sum_y));

        // Track some iterated exponential terms
        Scalar iter_y_inv = ONE; // y.inverse()**i
        Scalar iter_y_NM = y_NM; // y**(N*M - i)

        // Gi, Hi
        for (std::size_t i = 0; i < N*M; i++) {
            Scalar g = proof.ip_r1*e1*iter_y_inv;
            Scalar h = proof.ip_s1*e1;
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
            scalars[2*i] += w*(g + e1_square*z);
            
            // Hi
            scalars[2*i+1] += w*(h - e1_square*(d[i]*iter_y_NM+z));

            // Update the iterated values
            iter_y_inv *= y_inverse;
            iter_y_NM *= y_inverse;
        }

        // L, R
        for (std::size_t j = 0; j < rounds; j++) {
            points.emplace_back(proof.ip_L[j]);
            scalars.emplace_back(w*(e1_square.negate()*e[j].square()));
            points.emplace_back(proof.ip_R[j]);
            scalars.emplace_back(w*(e1_square.negate()*e_inverse[j].square()));
        }
    }

    // Add the common generators
    points.emplace_back(F);
    scalars.emplace_back(F_scalar);
    points.emplace_back(G);
    scalars.emplace_back(G_scalar);
    points.emplace_back(H);
    scalars.emplace_back(H_scalar);

    // Test the batch
    secp_primitives::MultiExponent multiexp(points, scalars);
    return multiexp.get_multiple().isInfinity();
}

}