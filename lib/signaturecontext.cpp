// @file signaturecontext.cpp - Implementation file for signature context class
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "signaturecontext.h"
#include "abs.h"

namespace lbcrypto {
  // Method for setting up a GPV context with specific parameters
  template <class Element> void SignatureContext<Element>::GenerateGPVContext(
    usint ringsize, usint bits, usint base) {

    usint sm = ringsize * 2;
    double stddev = SIGMA;
    typename Element::DggType dgg(stddev);
    typename Element::Integer smodulus;
    typename Element::Integer srootOfUnity;

    smodulus = FirstPrime<typename Element::Integer>(bits, sm);
    srootOfUnity = RootOfUnity(sm, smodulus);
    ILParamsImpl<typename Element::Integer> ilParams = ILParamsImpl<typename Element::Integer>(sm, smodulus, srootOfUnity);

    ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(srootOfUnity, sm, smodulus);
    DiscreteFourierTransform::PreComputeTable(sm);

    auto silparams = std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);
    m_params = std::make_shared<GPVSignatureParameters<Element>>(silparams, dgg, base);
    m_scheme = std::make_shared<GPVSignatureScheme<Element>>();
  }

  // Method for setting up a GPV context with desired security level only
  template <class Element>
  void SignatureContext<Element>::GenerateGPVContext(usint ringsize) {
    usint base, k;
    switch (ringsize) {
      case 512:
        k = 24;
        base = 8;
        break;
      case 1024:
        k = 27;
        base = 64;
        break;
      default:
        PALISADE_THROW(config_error, "Unknown ringsize");
    }
    GenerateGPVContext(ringsize, k, base);
  }

  // Method for key generation
  template <class Element>
  void SignatureContext<Element>::KeyGen(LPSignKey<Element>* sk,
                                         LPVerificationKey<Element>* vk) {
    m_scheme->KeyGen(m_params, sk, vk);
  }

  // Method for signing a given plaintext
  template <class Element>
  void SignatureContext<Element>::Sign(const LPSignPlaintext<Element>& pt,
                                       const LPSignKey<Element>& sk,
                                       const LPVerificationKey<Element>& vk,
                                       LPSignature<Element>* sign) {
    m_scheme->Sign(m_params, sk, vk, pt, sign);
  }


  // Method for offline phase of signing a given plaintext
  template <class Element>
  void SignatureContext<Element>::SignOfflinePhase(
    const LPSignKey<Element>& sk, PerturbationVector<Element>& pv) {
    pv = m_scheme->SampleOffline(m_params, sk);
  }

  // Method for online phase of signing a given plaintext
  template <class Element>
  void SignatureContext<Element>::SignOnlinePhase(
    const LPSignPlaintext<Element>& pt, const LPSignKey<Element>& sk,
    const LPVerificationKey<Element>& vk, const PerturbationVector<Element> pv,
    LPSignature<Element>* signatureText) {
    m_scheme->SignOnline(m_params, sk, vk, pv, pt, signatureText);
  }

  // Method for verifying the plaintext and signature
  template <class Element>
  bool SignatureContext<Element>::Verify(const LPSignPlaintext<Element>& pt,
                                         const LPSignature<Element>& signature,
                                         const LPVerificationKey<Element>& vk) {
    return m_scheme->Verify(m_params, vk, signature, pt);
  }

  // Method for key generation
  template <class Element>
  void SignatureContext<Element>::Setup(LPSignKey<Element>* sk,
                                        LPVerificationKey<Element>* vk) {
    m_scheme->KeyGen(m_params, sk, vk);
  }

  template <class Element>
  void SignatureContext<Element>::Extract(const LPSignKey<Element>& sk,
                                          const LPVerificationKey<Element>& vk,
                                          vector<string> attributes) {

    auto params = std::static_pointer_cast<GPVSignatureParameters<Element>>(m_params);
    const auto &signKey = static_cast<const GPVSignKey<Element> &>(sk);
    const auto &verificationKey = static_cast<const GPVVerificationKey<Element> &>(vk);

    // extract(params, sk, vk, attributes);
    auto key = extract(params, signKey, verificationKey, attributes);

    string msg = "ISSO EH UM TESTE";
    string msg2 = "ISSO EH UM TESTEa";

    auto signature = sign(params, key, verificationKey, msg, attributes);

    verify(params, verificationKey, msg, signature);
    // verify(params, verificationKey, msg2, signature);
  }
}  // namespace lbcrypto
