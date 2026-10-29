// CipherShape native boundary. OpenFHE supplies every cryptographic operation.
#include "openfhe.h"
#include "ciphertext-ser.h"
#include "ckks_serial.h"
#include "key/key-ser.h"
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/resource.h>
using namespace lbcrypto;
namespace fs = std::filesystem;
using CT = Ciphertext<DCRTPoly>;
constexpr uintmax_t MAX_FILE = 256ULL * 1024 * 1024;
void require(bool b) { if (!b) throw std::runtime_error("invalid artifact"); }
void bounded(const fs::path& p) { require(fs::is_regular_file(p) && fs::file_size(p)>0 && fs::file_size(p)<=MAX_FILE); }
template<class T> void save(const fs::path& p, const T& x) { require(Serial::SerializeToFile(p.string(),x,SerType::BINARY)); }
template<class T> void load(const fs::path& p, T& x) { bounded(p); require(Serial::DeserializeFromFile(p.string(),x,SerType::BINARY)); }
CryptoContext<DCRTPoly> context(const fs::path& dir) {
  CryptoContext<DCRTPoly> cc; load(dir/"context.bin",cc);
  require(cc && cc->GetRingDimension()>=8192 && cc->GetRingDimension()<=65536);
  return cc;
}
double number(std::istream& in) { double v; require(bool(in>>v)&&std::isfinite(v)&&std::abs(v)<=1e8); return v; }
std::vector<double> values(std::istream& in, size_t n) { require(n>0&&n<=32768); std::vector<double> v(n); for(auto& x:v)x=number(in); return v; }
Plaintext packed(CryptoContext<DCRTPoly>& cc, std::vector<double> v) {
  size_t slots=cc->GetRingDimension()/2; require(v.size()<=slots); v.resize(slots,0.0);
  return cc->MakeCKKSPackedPlaintext(v,1,0,nullptr,slots);
}
#ifdef CS_CLIENT
int main(int argc,char** argv) {
 try {
  require(argc>=3); std::string mode=argv[1]; fs::path pub=argv[2];
  if(mode=="keygen") {
    require(argc>=5); fs::path priv=argv[3]; int depth=std::stoi(argv[4]); require(depth>=2&&depth<=8);
    fs::create_directories(pub); fs::create_directories(priv); chmod(priv.c_str(),0700);
    require(!fs::exists(priv/"secret.bin")&&!fs::exists(pub/"context.bin"));
    CCParams<CryptoContextCKKSRNS> p;
    p.SetSecurityLevel(HEStd_128_classic); p.SetMultiplicativeDepth(depth);
    p.SetScalingModSize(45); p.SetFirstModSize(55); p.SetScalingTechnique(FLEXIBLEAUTO);
    auto cc=GenCryptoContext(p); cc->Enable(PKE); cc->Enable(KEYSWITCH); cc->Enable(LEVELEDSHE);
    auto kp=cc->KeyGen(); require(kp.good()); cc->EvalMultKeyGen(kp.secretKey);
    std::vector<int32_t> rotations;
    for(int i=5;i<argc;i++){int r=std::stoi(argv[i]); require(r!=0&&std::abs(r)<=64); rotations.push_back(r);}
    if(!rotations.empty())cc->EvalRotateKeyGen(kp.secretKey,rotations);
    save(pub/"context.bin",cc); save(pub/"public.bin",kp.publicKey); save(priv/"secret.bin",kp.secretKey); chmod((priv/"secret.bin").c_str(),0600);
    {std::ofstream f(pub/"mult.bin",std::ios::binary);require(cc->SerializeEvalMultKey(f,SerType::BINARY,kp.secretKey->GetKeyTag()));}
    if(!rotations.empty()){std::ofstream f(pub/"rot.bin",std::ios::binary);require(cc->SerializeEvalAutomorphismKey(f,SerType::BINARY,kp.secretKey->GetKeyTag()));}
    std::cout<<"{\"ring_dimension\":"<<cc->GetRingDimension()<<",\"slots\":"<<cc->GetRingDimension()/2<<",\"depth\":"<<depth<<",\"scale_bits\":45,\"first_mod_bits\":55,\"security\":\"HEStd_128_classic\",\"key_tag\":\""<<kp.secretKey->GetKeyTag()<<"\"}\n";
  } else if(mode=="encrypt") {
    require(argc==4); auto cc=context(pub); PublicKey<DCRTPoly> pk; load(pub/"public.bin",pk);
    size_t n; require(bool(std::cin>>n)&&n<=64); auto v=values(std::cin,n); save(argv[3],cc->Encrypt(pk,packed(cc,v)));
  } else if(mode=="decrypt") {
    require(argc==5); auto cc=context(pub); PrivateKey<DCRTPoly> sk; load(fs::path(argv[3])/"secret.bin",sk); CT ct; load(argv[4],ct);
    require(ct->GetKeyTag()==sk->GetKeyTag()); Plaintext pt; cc->Decrypt(sk,ct,&pt); pt->SetLength(cc->GetRingDimension()/2);
    auto v=pt->GetCKKSPackedValue(); double other=0; for(size_t i=1;i<v.size();i++)other=std::max(other,std::abs(v[i]));
    // This output stays on the client. Never send it to the server.
    std::cout<<std::setprecision(17)<<"{\"value\":"<<v[0].real()<<",\"result_imaginary_residual\":"<<std::abs(v[0].imag())<<",\"max_nonresult_slot\":"<<other<<"}\n";
  } else throw std::runtime_error("invalid mode");
  return 0;
 } catch(...) {std::cerr<<"client operation failed\n";return 2;}
}
#else
int main(int argc,char** argv) {
 try {
  require(argc==5);fs::path pub=argv[1],plan=argv[2],inputs=argv[3],outputs=argv[4];
  auto cc=context(pub); PublicKey<DCRTPoly> pk;load(pub/"public.bin",pk);
  bounded(pub/"mult.bin"); {std::ifstream f(pub/"mult.bin",std::ios::binary);require(cc->DeserializeEvalMultKey(f,SerType::BINARY));}
  if(fs::exists(pub/"rot.bin")){bounded(pub/"rot.bin");std::ifstream f(pub/"rot.bin",std::ios::binary);require(cc->DeserializeEvalAutomorphismKey(f,SerType::BINARY));}
  bounded(plan); std::ifstream f(plan); std::string line; std::map<int,CT> live; std::map<int,bool> masked; size_t peak=0,peak_bytes=0,count=0;
  fs::create_directories(outputs);
  auto start=std::chrono::steady_clock::now();
  std::ostringstream trace; trace<<"[";bool first=true;
  while(std::getline(f,line)) {
    require(++count<=4096 && line.size()<=16384); std::istringstream s(line); std::string op; int id; require(bool(s>>op>>id)&&id>=0&&id<65536);
    auto get=[&](int i)->CT{require(live.count(i));return live.at(i);};
    int a,b; CT out; auto op_start=std::chrono::steady_clock::now();
    if(op=="input") {int index; require(bool(s>>index)&&index>=0&&index<256);load(inputs/(std::to_string(index)+".bin"),out);require(out->GetKeyTag()==pk->GetKeyTag());require(out->GetCryptoContext()==cc);require(out->GetLevel()==0);}
    else if(op=="drop") {require(live.erase(id)==1);masked.erase(id);continue;}
    else if(op=="output") {int index;require(bool(s>>index)&&index>=0&&index<64&&masked[id]);save(outputs/(std::to_string(index)+".bin"),get(id));continue;}
    else if(op=="add"||op=="sub"||op=="mul") {require(bool(s>>a>>b)); if(op=="add")out=cc->EvalAdd(get(a),get(b));else if(op=="sub")out=cc->EvalSub(get(a),get(b));else out=cc->EvalMult(get(a),get(b));}
    else if(op=="scale") {require(bool(s>>a));out=cc->EvalMult(get(a),number(s));}
    else if(op=="weights") {size_t n;require(bool(s>>a>>n)&&n<=64);out=cc->EvalMult(get(a),packed(cc,values(s,n)));}
    else if(op=="rotate") {int r;require(bool(s>>a>>r)&&r!=0&&std::abs(r)<=64);out=cc->EvalRotate(get(a),r);}
    else if(op=="mask") {require(bool(s>>a));out=cc->EvalMult(get(a),packed(cc,{1.0}));}
    else throw std::runtime_error("invalid opcode");
    std::string extra;require(!(s>>extra)); require(!live.count(id)); require(out && out->GetKeyTag()==pk->GetKeyTag());live.emplace(id,out);masked[id]=(op=="mask");
    size_t bytes=0;for(auto& [k,c]:live)bytes+=c->GetElements().size()*c->GetElements()[0].GetNumOfElements()*cc->GetRingDimension()*sizeof(uint64_t);
    peak=std::max(peak,live.size());peak_bytes=std::max(peak_bytes,bytes);
    if(!first) { trace<<","; }
    first=false;
    trace<<"{\"op\":\""<<op<<"\",\"id\":"<<id<<",\"seconds\":"<<std::chrono::duration<double>(std::chrono::steady_clock::now()-op_start).count()<<",\"level\":"<<out->GetLevel()<<",\"scale\":"<<out->GetScalingFactor()<<",\"noise_scale_degree\":"<<out->GetNoiseScaleDeg()<<"}";
  }
  trace<<"]";double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
  struct rusage usage; require(getrusage(RUSAGE_SELF,&usage)==0);
#ifdef __APPLE__
  auto peak_rss=usage.ru_maxrss;
#else
  auto peak_rss=usage.ru_maxrss*1024;
#endif
  std::cout<<"{\"evaluation_seconds\":"<<elapsed<<",\"peak_live_ciphertexts\":"<<peak<<",\"peak_coefficient_bytes\":"<<peak_bytes<<",\"peak_rss_bytes\":"<<peak_rss<<",\"trace\":"<<trace.str()<<"}\n";
  return 0;
 }catch(...){std::cerr<<"evaluation failed\n";return 2;}
}
#endif
