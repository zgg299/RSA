#include <gmpxx.h>
#include <iostream>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <cstdlib>
using namespace std;
 
#define KEY_LENGTH 2048  //Length of public key
#define BASE 16    //Input and output digits
 
struct key_pair
{
  char * n;
  char * d;
  int e;
};
void writefile(char *p,string filename); 
//Generate two large prime numbers
mpz_t * gen_primes()
{										
  gmp_randstate_t grt;				
  gmp_randinit_default(grt);	
  gmp_randseed_ui(grt, time(NULL));
	
  mpz_t key_p, key_q;
  mpz_init(key_p);
  mpz_init(key_q);
 
  mpz_urandomb(key_p, grt, KEY_LENGTH / 2);		
  mpz_urandomb(key_q, grt, KEY_LENGTH / 2);	//Random Generation of Two Large Integers
 
  mpz_t * result = new mpz_t[2];
  mpz_init(result[0]);
  mpz_init(result[1]);
 
  mpz_nextprime(result[0], key_p);  //Using the Prime Generation Function of GMP
  mpz_nextprime(result[1], key_q);
  char * buf_p = new char[KEY_LENGTH + 10];
  char * buf_q = new char[KEY_LENGTH + 10];

  mpz_get_str(buf_p, BASE, key_p);
  writefile(buf_p,"p.txt");
  mpz_get_str(buf_q, BASE, key_q);
  writefile(buf_q,"q.txt");
 
  mpz_clear(key_p);
  mpz_clear(key_q);
 
  return result;	
}
 
//Generate key pairs
key_pair * gen_key_pair()
{
  mpz_t * primes = gen_primes();
 
  mpz_t key_n, key_e, key_f;
  mpz_init(key_n);
  mpz_init(key_f);
  mpz_init_set_ui(key_e, 65537);	//set e as 65537
 
  mpz_mul(key_n, primes[0], primes[1]);		//caculate n=p*q
  mpz_sub_ui(primes[0], primes[0], 1);		//p=p-1
  mpz_sub_ui(primes[1], primes[1], 1);		//q=q-1
  mpz_mul(key_f, primes[0], primes[1]);		//caculate ¦Õ(n)=(p-1)*(q-1)
 
  mpz_t key_d;	
  mpz_init(key_d);
  mpz_invert(key_d, key_e, key_f);
 
  key_pair * result = new key_pair;
 
  char * buf_n = new char[KEY_LENGTH + 10];
  char * buf_d = new char[KEY_LENGTH + 10];
 
  mpz_get_str(buf_n, BASE, key_n);
  result->n = buf_n;
  mpz_get_str(buf_d, BASE, key_d);
  result->d = buf_d;
  result->e = 65537;
 
  mpz_clear(primes[0]);   
  mpz_clear(primes[1]);
  mpz_clear(key_n);
  mpz_clear(key_d);
  mpz_clear(key_e);
  mpz_clear(key_f);
  delete []primes;
 
  return result;
}
 
//Encryption function
char * encrypt(const char * plain_text, const char * key_n, int key_e)  
{
  mpz_t M, C, n;
  mpz_init_set_str(M, plain_text, BASE); 
  mpz_init_set_str(n, key_n, BASE);
  mpz_init_set_ui(C, 0);
 
  mpz_powm_ui(C, M, key_e, n);    //Computing Functions Using Modular Power in GMP
 
  char * result = new char[KEY_LENGTH + 10];
  mpz_get_str(result, BASE, C);
 
  return result;
}

 
//decryption
char * decrypt(const char * cipher_text, const char * key_n, const char * key_d)  
{
  mpz_t M, C, n, d;
  mpz_init_set_str(C, cipher_text, BASE); 
  mpz_init_set_str(n, key_n, BASE);
  mpz_init_set_str(d, key_d, BASE);
  mpz_init(M);
 
  mpz_powm(M, C, d, n);   //Computing Functions Using Modular Power in GMP
 
  char * result = new char[KEY_LENGTH + 10];
  mpz_get_str(result, BASE, M);
 
  return result;
}

//Correctness test
void test(){
  int e = 65537;
  char str_n[] = "73299B42DBD959CDB3FB176BD1";
  char str_d[] = "63C3264A0BF3A4FC0FF0940935";
  char buf[KEY_LENGTH + 10];
  cout<<"Please enter the number to be encrypted. The length of the binary system does not exceed the length of the binary system."<<KEY_LENGTH<<endl;
  cin>>buf;

  char * cipher_text = encrypt(buf, str_n, e);
  cout<<"The ciphertext is:"<<cipher_text<<endl;
  char * plain_text = decrypt(cipher_text, str_n, str_d);
  cout<<"Plaintext is:"<<plain_text<<endl;
} 

void readfile(char str[], string filename){
  FILE *fp=fopen(filename.c_str(),"r");  
  if(fp==NULL){
    printf("file open failed");
    exit(-1);
  }
  while(!feof(fp))
    fscanf(fp,"%s",str);
  
  fclose(fp);
}

void writefile(char *p,string filename){
  FILE *fp=fopen(filename.c_str(),"w+");
  if(fp==NULL){
    printf("Failed to open the file!");
    exit(-1);
  }
  if(fputs(p,fp)==EOF)printf("Failed to open the file!");
  fclose(fp);
}

void write_e(string filename){
  FILE *fp=fopen(filename.c_str(),"w+");
  if(fp==NULL){
    printf("file open failed");
    exit(-1);
  }
  if(fputs("65537",fp)==EOF)printf("write file error!");
  fclose(fp);
}
string get_value(string key, int argc, char *argv[]){
  for(int i=0; i < argc; i++){
    if(argv[i]==key)return argv[i+1];
  }
  return "";
}

int main(int argc, char *argv[])
{ 
  //test();
  string pfile = get_value("-p", argc, argv);
  string nfile = get_value("-n", argc, argv);
  string efile = get_value("-e", argc, argv);
  string dfile = get_value("-d", argc, argv);
  string cfile = get_value("-c", argc, argv);
  if (pfile.empty() && efile.empty() && nfile.empty())printf("cmd line is error!\n");

  key_pair * p = gen_key_pair();

  cout<<"n = "<<p->n<<endl;
  cout<<"\n"<<endl;
  cout<<"d = "<<p->d<<endl;
   cout<<"\n"<<endl;
  cout<<"e = "<<p->e<<endl;
   cout<<"\n"<<endl;
  writefile(p->n, nfile);
  writefile(p->d, dfile);
  write_e(efile);
  
 
  char buf1[KEY_LENGTH + 10], buf2[KEY_LENGTH + 10];
  if((!pfile.empty()) && (!cfile.empty())){
     readfile(buf1, pfile);
   
     cout<<"encryption starts!"<<endl;
     char *cipher_text = encrypt(buf1, p->n, p->e);
     cout<<"The ciphertext is:"<<cipher_text<<endl;
     writefile(cipher_text, cfile);
     cout<<"\n"<<endl;

     readfile(buf2, cfile);
     cout<<"decryption starts!"<<endl;
     char* plain_text = decrypt(buf2, p->n, p->d);
     cout<<"Plaintext is:"<<plain_text<<endl;
     writefile(plain_text, pfile);
  }
 else
    printf("cmd line is error!\n");
  
  return 0;
}

