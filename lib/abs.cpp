#include "abs.h"
#include "math/matrix.h"
#include "signature/gpv.h"
#include "signaturecontext.h"
#include "utils/inttypes.h"
#include "utils/memory.h"
#include <bits/stdint-uintn.h>
#include <iostream>
#include <memory>
#include <ostream>
#include <ratio>
#include <string>
#include <vector>

using namespace lbcrypto;

// Setups the Attribute Authority keys and public parameters
// Dummy for now (using the GPV normal keygen)
void setup() {}

// Public Syndrome matrix generator from a given set of attributes
void attributeHashGenerator(vector<string> attributes, shared_ptr<GPVSignatureParameters<Poly>> m_params, Matrix<Poly> *attributesSyndrome) {
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(PlaintextModulus(512)));
    vector<int64_t> digest;
    Poly u;

    for (auto i = attributes.begin(); i != attributes.end(); ++i) {
        for (int j = 0; j < 32; j++) {
            string auxAttr = std::to_string(j) + *i;

            lbcrypto::HashUtil::Hash(auxAttr, lbcrypto::SHA_256, digest);
            lbcrypto::Plaintext hashedText(std::make_shared<lbcrypto::CoefPackedEncoding>(
                                               m_params->GetILParams(), ep, digest));

            // erase the digest value before the next use
            digest.clear();

            hashedText->Encode();
            u = hashedText->GetElement<Poly>();
            u.SwitchFormat();

            // Sums the current attributes with the next one
            (*attributesSyndrome)(0, j) = (*attributesSyndrome)(0, j) + u;
        }
    }

    return;
}

vector<shared_ptr<Matrix<Poly>>> extract(shared_ptr<GPVSignatureParameters<Poly>> m_params,
                                         const lbcrypto::GPVSignKey<Poly> &signKey,
                                         const lbcrypto::GPVVerificationKey<Poly> &verificationKey,
                                         vector<string> attributes) {

    // Getting parameters for calculations
    size_t n = m_params->GetILParams()->GetRingDimension();
    size_t k = m_params->GetK();
    size_t base = m_params->GetBase();
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(PlaintextModulus(512)));

    shared_ptr<typename Poly::Params> params = m_params->GetILParams();
    auto zero_alloc = Poly::Allocator(params, EVALUATION);

    Matrix<Poly> syndromeMatrix(zero_alloc, 1, 32);

    attributeHashGenerator(attributes, m_params, &syndromeMatrix);

    // Getting the trapdoor, its public matrix, perturbation matrix and gaussian
    // generator to use in sampling
    const Matrix<Poly> &A = verificationKey.GetVerificationKey();
    const RLWETrapdoorPair<Poly> &T = signKey.GetSignKey();
    typename Poly::DggType &dgg = m_params->GetDiscreteGaussianGenerator();

    typename Poly::DggType &dggLargeSigma = m_params->GetDiscreteGaussianGeneratorLargeSigma();

    vector<shared_ptr<Matrix<Poly>>> attributesKey;

    for (int i = 0; i < static_cast<int>(syndromeMatrix.GetCols()); i++) {
        auto u = syndromeMatrix(0, i);
        Matrix<Poly> zHat = RLWETrapdoorUtility<Poly>::GaussSamp(
            n, k, A, T, u, dgg, dggLargeSigma, base);
        attributesKey.push_back(std::make_shared<Matrix<Poly>>(zHat));
    }

    ///////////////////////////////////////////////////////////////////////////
    //                                  TESTING                              //
    ///////////////////////////////////////////////////////////////////////////

    // std::cout << "ATTR" << std::endl << (syndromeMatrix).GetData() << std::endl;

    // auto stddev = m_params->GetDiscreteGaussianGenerator().GetStd();
    // auto gaussian_alloc = Poly::MakeDiscreteGaussianCoefficientAllocator(
    //     params, COEFFICIENT, stddev);

    // // Sample a discrete y vector
    // Matrix<Poly> y(zero_alloc, A.GetCols(), A.GetRows(), gaussian_alloc);
    // y.SwitchFormat();

    // Poly secret = (A * y)(0, 0);

    // std::cout << "SECRET" << std::endl << secret.GetValues() << std::endl;

    // Poly test = syndromeMatrix(0, 0);
    // Poly test2 = syndromeMatrix(0, 1);
    // Poly test3 = syndromeMatrix(0, 6);
    // Poly test4 = syndromeMatrix(0, 9);

    // Poly test5 = test + test2 + test3 + test4;

    // std::cout << test5.GetValues() << std::endl;

    // Matrix<Poly> z1 = *attributesKey[0];
    // Matrix<Poly> z2 = *attributesKey[1];
    // Matrix<Poly> z3 = *attributesKey[6];
    // Matrix<Poly> z4 = *attributesKey[9];

    // Matrix<Poly> z5 = z1 + z2 + z3 + z4 + y;

    // Poly result = (A * z5)(0, 0);

    // Poly resultFinal = result - test5;

    // std::cout << "SIGNAT" << std::endl << resultFinal.GetValues() << std::endl;

    return attributesKey;
}

signatureABS sign(shared_ptr<GPVSignatureParameters<Poly>> m_params,
                  vector<shared_ptr<Matrix<Poly>>> attributesKey,
                  const lbcrypto::GPVVerificationKey<Poly> &verificationKey,
                  string message,
                  vector<string> attributeList){

    EncodingParams ep(std::make_shared<EncodingParamsImpl>(PlaintextModulus(512)));

    // Get parameters from keys
    shared_ptr<typename Poly::Params> params = m_params->GetILParams();
    auto stddev = m_params->GetDiscreteGaussianGenerator().GetStd();

    auto zero_alloc = Poly::Allocator(params, EVALUATION);
    auto gaussian_alloc = Poly::MakeDiscreteGaussianCoefficientAllocator(
        params, COEFFICIENT, stddev);

    const Matrix<Poly> &A = verificationKey.GetVerificationKey();

    // Sample a discrete y vector
    Matrix<Poly> y(zero_alloc, A.GetCols(), A.GetRows(), gaussian_alloc);
    y.SwitchFormat();

    Poly secret = (A * y)(0, 0);

    std::cout << "SECRET" << std::endl << secret.GetValues() << std::endl;

    vector<int64_t> digest;

    string secretWithMessage;

    for (usint i = 0; i < secret.GetLength(); i++) {
        secretWithMessage.append(secret[i].ToString());
    }

    secretWithMessage.append(message);

    // std::cout << "secretWithMessage" << std::endl << secretWithMessage << std::endl;

    lbcrypto::HashUtil::Hash(secretWithMessage, lbcrypto::SHA_256, digest);
    lbcrypto::Plaintext hashedText(std::make_shared<lbcrypto::CoefPackedEncoding>(
                                       m_params->GetILParams(), ep, digest));

    uint32_t h = 0;

    h += ((uint32_t)(digest[0] & 0xFF)) << 24;
    h += ((uint32_t)(digest[1] & 0xFF)) << 16;
    h += ((uint32_t)(digest[2] & 0xFF)) << 8;
    h += ((uint32_t)(digest[3] & 0xFF));

    std::cout << "h: " << std::hex << h << std::dec << std::endl;
    std::cout << "h (bin): " << std::bitset<32>(h) << std::endl;

    Matrix<Poly> sig = y;

    for (int i = 0; i < 32; i++) {
        if ((h >> (31 - i)) & 0x1) {
            std::cout << i << " ";
            sig += *attributesKey[i];
        }
    }
    std::cout << std::endl;

    // std::cout << "sig:" << sig.GetData() << std::endl;

    signatureABS *signature = new signatureABS(attributeList, h, sig);

    ///////////////////////////////////////////////////////////////////////////
    //                                  TESTING                              //
    ///////////////////////////////////////////////////////////////////////////

    Poly sigAux2(params, EVALUATION, true);

    Matrix<Poly> syndromeMatrix(zero_alloc, 1, 32);
    attributeHashGenerator(attributeList, m_params, &syndromeMatrix);

    for (int i = 0; i < 32; i++) {
        if ((h >> (31 - i)) & 0x1) {
            std::cout << i << " ";
            sigAux2 += syndromeMatrix(0, i);
        }
    }
    std::cout << std::endl;

    std::cout << "Aux2" << sigAux2.GetValues() << std::endl;

    Poly ver = (A * sig)(0, 0);

    std::cout << "ver" << ver.GetValues() << std::endl;

    Poly result = ver - sigAux2;

    std::cout << "result" << result.GetValues() << std::endl;

    return *signature;
}

bool verify(shared_ptr<GPVSignatureParameters<Poly>> m_params,
            const lbcrypto::GPVVerificationKey<Poly> &verificationKey,
            string message,
            signatureABS signature){

    std::cout << "VERIFY" << std::endl;

    EncodingParams ep(std::make_shared<EncodingParamsImpl>(PlaintextModulus(512)));
    vector<string> attributeList = signature.getAttributeList();
    auto z = signature.getSignature();
    unsigned int h = signature.getSignatureHash();

    shared_ptr<Poly::Params> params = m_params->GetILParams();
    auto zero_alloc = Poly::Allocator(params, EVALUATION);

    Matrix<Poly> syndromeMatrix(zero_alloc, 1, 32);

    attributeHashGenerator(attributeList, m_params, &syndromeMatrix);

    // std::cout << "ATTR" << std::endl << (syndromeMatrix).GetData() << std::endl;

    // std::cout << "h: " << std::hex << h << std::dec << std::endl;
    // std::cout << "h (bin): " << std::bitset<32>(h) << std::endl;
    // std::cout << "sig:" << z.GetData() << std::endl;

    const Matrix<Poly> &A = verificationKey.GetVerificationKey();

    Poly sigAux = (A * z)(0, 0);
    // sigAux.SwitchFormat();

    std::cout << "ver" << sigAux.GetValues() << std::endl;

    Poly sigAux2(params, EVALUATION, true);

    // std::cout << "AUX" << std::endl << sigAux2.GetValues() << std::endl;

    for (int i = 0; i < 32; i++) {
        if ((h >> (31 - i)) & 0x1) {
            std::cout << i << " ";
            sigAux2 += syndromeMatrix(0, i);
        }
    }

    std::cout << "Aux2" << sigAux2.GetValues() << std::endl;

    std::cout << std::endl;

    Poly sigComparator = sigAux - sigAux2;

    std::cout << "result" << sigComparator.GetValues() << std::endl;

    // std::cout << "sigComparatorString" << std::endl << sigComparator.GetValues() << std::endl;

    string sigComparatorString;
    for (uint i = 0; i < sigComparator.GetLength(); i++) {
        sigComparatorString.append(sigComparator[i].ToString());
    }

    // std::cout << "sigComparatorString" << std::endl << sigComparatorString << std::endl;

    sigComparatorString.append(message);

    vector<int64_t> digest;
    lbcrypto::HashUtil::Hash(sigComparatorString, lbcrypto::SHA_256, digest);
    lbcrypto::Plaintext hashedText(std::make_shared<lbcrypto::CoefPackedEncoding>(
                                       m_params->GetILParams(), ep, digest));

    std::cout << "HASH" << std::endl;

    std::cout << std::hex << h;
    std::cout << std::dec << std::endl;

    std::cout << "VER" << std::endl;

    for (usint i = 0; i < 8; i++) {
        std::cout << std::hex << digest[i];
    }

    std::cout << std::dec << std::endl;

    return true;
}
