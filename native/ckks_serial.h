//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

// CipherShape adaptation of OpenFHE 1.6.1 cryptocontext-ser.h and
// scheme/ckksrns/ckksrns-ser.h. Binary CKKS only; no crypto changes.
#pragma once
#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-scheme.h"
#include "utils/serial.h"
CEREAL_REGISTER_TYPE(lbcrypto::CryptoParametersCKKSRNS);
CEREAL_REGISTER_TYPE(lbcrypto::SchemeCKKSRNS);
CEREAL_REGISTER_POLYMORPHIC_RELATION(lbcrypto::CryptoParametersRNS, lbcrypto::CryptoParametersCKKSRNS);
CEREAL_CLASS_VERSION(lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>, lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>::SerializedVersion());
namespace lbcrypto {
namespace internal_cc_traits {
template <typename Element> struct cc_ser_enabled<CryptoContextImpl<Element>> : std::true_type {};
template <typename Element> struct cc_ser_enabled<std::shared_ptr<CryptoContextImpl<Element>>> : std::true_type {};
}
namespace Serial {
template <typename T>
void Deserialize(CryptoContext<T>& obj, std::istream& stream, const SerType::SERBINARY&) {
    CryptoContext<T> newob;
    cereal::PortableBinaryInputArchive archive(stream);
    archive(newob);
    obj = CryptoContextFactory<T>::GetContext(newob->GetCryptoParameters(), newob->GetScheme(), newob->getSchemeId());
}
template <typename T>
bool DeserializeFromFile(const std::string& filename, CryptoContext<T>& obj, const SerType::SERBINARY& type) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file.is_open()) return false;
    Serial::Deserialize(obj, file, type);
    return true;
}
}
}
