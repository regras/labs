#ifndef __ABS_H_
#define __ABS_H_

#include <bits/stdint-uintn.h>
#include <iostream>
#include <string>
#include <vector>
#include "math/matrix.h"
#include "signature/signaturecontext.h"

using namespace lbcrypto;

const std::string attributesList[] = {
    "Undergrad",
    "Graduate",
    "Professor",
    "Electrical Engineering",
    "Computer Science"
};

class signatureABS {
    public:
        signatureABS(vector<string> attributesList, uint32_t signatureHash, Matrix<Poly> signature) {
            this->attributeList = attributesList;
            this->signatureHash = signatureHash;
            this->signature = signature;
        }

        vector<string> getAttributeList() {return this->attributeList;}
        void setAttributeList(vector<string> attributeList) {this->attributeList = attributeList;}

        uint32_t getSignatureHash() {return this->signatureHash;}
        void setSignatureHash(uint32_t signatureHash) {this->signatureHash = signatureHash;}

        Matrix<Poly> getSignature() {return this->signature;}
        void setSignature(Matrix<Poly> signature) {this->signature = signature;}
    private:
        vector<string> attributeList;
        uint32_t signatureHash;
        Matrix<Poly> signature;
};

void attributeHashGenerator(vector<string> attributes,
                            shared_ptr<LPSignatureParameters<Poly>> sparams,
                            Matrix<Poly> *syndromeMatrix);

vector<shared_ptr<Matrix<Poly>>> extract(shared_ptr<lbcrypto::GPVSignatureParameters<Poly>> sparams,
             const lbcrypto::GPVSignKey<Poly> &sk,
             const lbcrypto::GPVVerificationKey<Poly> &vk,
             vector<string> attributes);

signatureABS sign(shared_ptr<GPVSignatureParameters<Poly>> m_params,
                  vector<shared_ptr<Matrix<Poly>>> attributesKey,
                  const lbcrypto::GPVVerificationKey<Poly> &vrificationKey,
                  string message,
                  vector<string> attributeList);

bool verify(shared_ptr<GPVSignatureParameters<Poly>> m_params,
            const lbcrypto::GPVVerificationKey<Poly> &verificationKey,
            string message,
            signatureABS signature);

#endif // __ABS_H_
