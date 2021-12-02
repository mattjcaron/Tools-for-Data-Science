# PROVABLEPRIME, Generation of provable primes with Maurer's algorithm, with
# illustrative coding of RSA encryption (with authentication) and digital
# signature for sequences of fixed-sized plaintext blocks and RSA PRBG.


# Prologue.


# Generation of large pseudo-random primes for use in public key processing has
# in the practice commonly been done with a probabilistic method based on a
# primality test due to Miller and Rabin [1, 2]. Though the method has a fairly
# simple algorithm, it leaves in our view yet something non-trivial to be
# desired due to the fact that, while one could rather efficiently achieve any
# arbitrarily small probability of error of the result in general, a
# theoretically 100% sure proof of its primaility couldn't be obtained thereby
# (We assume that in the Miller-Rabin test the bases employed are randomly
# chosen. cf. also [3].)
#
# [1] A. Menezes et al., Handbook of Applied Cryptography (HAC), p.139, CRC
#     Press, 5th printing 2011. Freely available: http://cacr.uwaterloo.ca/hac/
# [2} J. Pieprzyk et al., Fundamentals of Computer Security, pp.179-180, Berlin,
#     2003.
# [3] F. Arnaut, Rabin-Miller Test: Composite Numbers which Pass It, Math.
#     Comp., vol. 64, pp.355-361, 1995.

# A practical algorithm of generation of large pseudo-random primes that are
# provably prime is due to Maurer [4]. To our knowledge, to this day no
# implementation of it in any popular programming languages is yet available to
# the public. Since Maurer's algorithm not only has the virtue of delivering
# provable primes but is also in processing time well comparable to the
# algorithm based on the Miller-Rabin test (for sizes of primes of practical
# interest, see comparison below), we have coded it in Python according to its
# description in [1, p.153]. It is hoped that the present code, being easily
# readable and thus simply verifiable to be correct, could be well useful to
# those who desire to develop for themselves certain unconditionally required
# parts of public key security software entirely independent of the currently
# existing risky huge, open-source (and certainly any non-open-soruce) PKI
# packages. See Epilogue at the end of this document for a discussion of such
# risks, where a simple yet practically impossible to be detected method of
# embdding a backdoor into RSA non-open-source software is detailed. (In fact,
# a strong personal desire of freedom from dependencies on the existing risky
# PKI packages and of exclusive usage of codes that he can really read,
# understand and verify in all details has motivated the present author to write
# this package.) In this connection particular attention may be called to the
# fact that A. K. Lenstra et al. in an extensive examination of the RSA moduli
# used in practice (http://infoscience.epfl.ch/record/174943/files/eprint.pdf,
# p.10) wrote that they "could not explain the relative frequencies and
# appearance of the occurrence of duplicate RSA moduli and depth one trees"
# found in their study. One highly possible cause would apparently be backdoors
# in the software being employed for RSA key generations. (See also my post on
# security risks of shared prime factors among RSA moduli employed in practice:
# http://s13.zetaboards.com/Crypto/topic/7487358/1/)
#
# [4] U. Maurer, Fast Generation of Prime Numbers and Secure Public-key
#     Cryptographic Parameters, J. Cryptology, 8(1955), 123-155.

# Note that most of the complex and/or very poorly documented components of the
# existing PKI packages are irrelevant for our targeted users, the common
# people, who mostly need only straightforward encryption and (less frequently)
# digital signature processing on relatively low volume stuffs, and (perhaps
# very rarely) pseudo-random bit sequences, and that these really necessary
# tasks have been successfully implemented in our illustrative Example 3, 4, 3S
# and 5 further below with entirely acceptable runtime efficiency.

# The following examples of use of provableprime() are given in the Appendix,
# which are followed by a test of Python's PRNG (using system randomness).
# Ex. 3S should be highly useful for our target users, since it is presumably
# the normal case that both communication partners have public keys.
#
# Example 1: Generation of a pseudo-random provable prime of desired size.
#
# Example 2: Generation of RSA keys (satisfying certain desirable constraints).
#
# Example 3: RSA block encryption processing with authentication (integrity
#            check).
#
# Example 4: RSA digital signature processing.
#
# Example 3S: RSA block encryption processing with authentication (integrity
#             check) and signature of the sender.
#
# Example 5: RSA pseudo-random bit generation.
#
# For each example, cpu time measurement is done.


# Sketch of some major components of this software:

# provableprime(): This is the kernel of this software. See above.

# rsakeygeneration(): Generates RSA public and private keys (with
# consideration of recommendationns of a report of ENISA on key sizes and
# parameters).

# encrypttoct(): Encrypts a sequence of blocks of constant size of mb bits,
# on the one side applying the for RSA known method of transformation 
# on the individual blocks, on the other side using certain commonly in
# symmetric block encryption employed methods, namely plaintext-and-ciphertext-
# block-chaining (with a pseudo-random IV). A sequence of blocks that stems from
# the plaintext of the user can thus be encrypted with RSA. (Note that this is
# a direct encryption of plaintext material with the help of RSA and not an
# encryption of a key for e.g. AES with RSA and afterwards an encryption of the
# plaintext with AES). Based on this function are the functions 
# rsaencryptplaintexttoct() and rsaencryptbytearraytoct(), which process a
# user-given plaintext string and byte sequence respectively.

# rsasigndocument(): Signs a document as follows: The document is first
# processed in the same way as above for encryption and then the IV used
# therein and the last chaining-value obtained are transformed with RSA using
# the private key of the person who signs. The pair of the resulting two
# numbers serves as the signature of the document.

# rsaprbggenbits(): Generates a cryptographically secure pseudo-random bit
# sequence with RSA.

# It may be particularly stressed that (see also Epilogue):

# (1) This software is self-sufficient to be employed for the purpose of
# end-to-end encryption-protected communications of the common people. See
# Example 3 and 3S further below. It does not involve hash-functions, nor need
# additional use of any symmetric encryption software like AES, though multiple
# encryption, i.e. protected transfer with it of already otherwise encrypted
# materials, can of course be done, if desired. (cf. e.g. packages like PGP in
# which, besides RSA (or ElGamal), algorithms of IDEA and SHA (or their
# alternatives) are involved and which have further a huge volume of codes to be
# examined and consequently, being practically inconvenient or impossible for
# independent experts to closely examine, are a significant source of security
# risks, as recent history of commonly employed PKI software has clearly shown.)
# Hence for communications of n persons only n RSA private keys need to be
# securely guarded secret. Measurement showed that, with the parameter values
# employed in Example 3S, the encryption and decryption cpu times on a common PC
# for a message of 10000 characters are 2 and 4 sec respectively, which is
# evidently acceptable for our targeted users, the common people.

# (2) For a sufficiently small group of persons who (transitively) know one
# another well: (a) Ensuring the genuineness of the RSA public keys is
# generally not a problem and hence no CA is needed for that. The public keys
# could namely be either directly physically transferred or e.g. sent as
# hex-sequences via email and verified over a voice channel. (b) For eventuall
# needs of CA-functionalities one person could serve as CA, employing digital
# signature as given in Example 4 further below.

# (3) Since for our targeted users it is very likely the case that sender and
# receiver of messages both have public keys, Example 3S should be of
# significant value to their communications.

# The following is a comparison of average runtime in sec. on a common PC of
# generation of primes of different bit sizes with the function provableprime()
# further below and with the commonly employed probabilistic procedure, i.e.
# generating a random odd number and testing it for primality first via trial
# division by an appropriate set of small primes and then via the Miller-Rabin
# test for diverse values of t (on failure either increment the number by 2 or
# generate a new random odd number and continue the trial):
#
# bits   provp    t=1    t=2    t=3    t=4    t=5    t=10   t=20   t=30   t=40
#
#  500   0.073   0.040  0.042  0.044  0.045  0.046  0.050  0.059  0.074  0.085
#
# 1000   0.494   0.313  0.335  0.347  0.352  0.366  0.383  0.436  0.534  0.578
#
# 1500   1.851   1.104  1.168  1.181  1.241  1.334  1.450  1.513  1.791  1.940
#
# 2000   5.080   3.169  3.253  3.342  3.495  3.610  3.779  4.044  4.362  4.952
#
# This indicates that Maurer's algorithm could be fairly competitive with the
# probabilistic procedure in processing speed for higher values of t of the
# Miller-Rabin test. (Presumably this is also true for implementatons in other
# programming languages.)

# The software is written with priority being given to ease of understanding by
# persons new to Python (and eventual porting to other PLs) rather than to
# elegance of coding and optimal processing speed.

# It may be remarked that the kernel of this software, provableprime(), together
# with functions it depends on, has a total number of code lines of 123 only.
# All the rest are either code lines for the examples or are comment lines.


# Version 2.1, released on 13.03.2016.

# Update notes:

# Version 1.0: Released on 03.09.2014.  
#
# Version 1.0.1: 18.09.2014: Addition of four functions to write to and read
# from files as convenience utilities.

# Version 1.1: 10.10.2014: Addition of Example 5 (RSA PRBG) and modification of
# plaintextstringtopt() to provide pseudo-random padding in Example 3.

# Version 1.1.1: 05.11.2014 : Modification of codes of Example 3 such that it
# can encrypt either a plaintext string or a byte sequence.

# Version 1.1.2: 03.12.2014: Improvement of a function used in the illustrative
# Example 3 and 4.

# Version 1.1.3: 15.07.2015: Removal of tiny coding redundancies.

# Version 1.2: 03.09.2015: Use of Python's SystemRandom class for random number
# generation.

# Version 1.2.1: 04.10.2015: Addition of a few checks of some user parameter
# input values.

# Version 1.2.2: 30.11.2015: Addition of checks in rsaprbgmodulusgeneration().

# Version 1.2.3: 01.12.2015: Improvement of rsaprbgmodulusgeneration().

# Version 2.0: 10.03.2016: Addition of Example 3S, RSA block encryption with
# authentication and signature. Addition of a check into provableprime().

# Version 2.1: 13.03.2016: Modification of provableprime() to render a check
# unnecessary.


# Code lines of documents with the same version number are always identical.
# There may be interim modifications of comment lines. The most recent document
# of PROVABLEPRIME can be obtained from:
# http://s13.zetaboards.com/Crypto/topic/7234475/1/


# This software may be freely used:

# 1. for all personal purposes unconditionally and

# 2. for all other purposes under the condition that its name, version number 
#    and authorship are explicitly mentioned and that the author is informed of
#    all eventual code modifications done.


# The author is indebted to TPS for review and suggestions throughout
# PROVABLEPRIME's development phase. Thanks are also due to CWL whose comments
# led to the enhancements in Version 2.0. Any remaining deficiencies of the
# software are however the sole responsibilty of the author.

# Constructive critiques, comments and suggestions of extensions and
# improvements are sincerely solicited. Address of the author:
#import math,random,pickle,time
# Email: mok-kong.shen@t-online.de
#
# Mail: Mok-Kong Shen, Postfach 340238, Munich 80099, Germany
#
# (Sender data optional, if no reply is required.)



################################################################################



import math,random,pickle,time



# The Euclidean algorithm for gcd.

def gcd(a,b):
  while a!=0:
    a,b=b%a,a
  return(b)


# Find the inverse of a mod n, cf. Wiki, Extended Euclidean algorithm.

def modinv(a,n):
  t,nt=0,1
  r,nr=n,a
  while nr!=0:
    q=r//nr
    t,nt=nt,t-q*nt
    r,nr=nr,r-q*nr
  if r>1:
    return None
  while t<0:
    t+=n
  return(t)


# The initial constellation of the table of small primes.

ptab=[2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71]


# ptab, the table of small primes, will be extended, if necessary, to have its
# last element not less than trialdivbound. (Sieve of Eratosthenes is used.)

def checkptab(trialdivbound):
  global ptab
  g=ptab[-1]
  while ptab[-1]<trialdivbound:
    g+=2
    h=math.ceil(math.sqrt(g))
    for p in ptab:
      if p>h:
        suc=1
        break
      if (g%p)==0:
        suc=0
        break
    if suc==0:
      continue
    ptab+=[g]
  return


# We extend ptab by default to a size appropriate for primality test with trial
# division for numbers up to 20 bits (this is required in the first part of the
# function provableprime() further below).

checkptab(2**10)


# Apply t rounds of the Miller-Rabin test to n.
#
# Return value: 0: n is composite.
#
#               1: n passes t rounds of the strong probable prime test.
#
# Set kn=1, if the first round is to use a=2, else set kn=0.
#
# See [1, p.139].
#
# We use this test only to improve the efficiency of Maurer's algorithm, see
# comments in provableprime() futher below.

def millerrabin(n,t,kn):
  assert t >= 1 and 0 <= kn <= 1
  if n<=3:
    if n>1:
      return(1)
    return(0)
  elif n%2==0:
    return(0)
  RANDOM=random.SystemRandom()
  r=n1=n-1
  s=0
  while (r%2)>0:
    s+=1
    r//=2
  s1=s-1
  for i in range(t):
    if i==0 and kn==1:
      a=2
    else:
      a=RANDOM.randint(2,n-2)    
    y=pow(a,r,n)
    if y!=1 and y!=n1:
      j=1
      while j<=s1 and y!=n1:
        y=(y*y)%n
        if y==1:
          return(0)      
        j+=1
      if y!=n1:
        return(0)
  return(1)

# Generate a random odd number n (2**k > n > 2**(k-1), k >= 2) with proveable
# primality employing Maurer's algorithm (the (k-1)-th bit of n is 1).
# Cf. sec.4.62 of HAC [1, p.153].

def provableprime(k):
  global ptab
  RANDOM=random.SystemRandom()
# The default size of ptab (see above) is sufficiently large for cases k<=20.
  if k<=20:
    while True:
# Select a random odd integer in the interval [2**(k-1), 2**k-1] (A. J. Menezes,
# personal communication).
      n=RANDOM.randint(2**(k-1),2**k-1)|1
      h=math.ceil(math.sqrt(n))
      for p in ptab[1:]:
        if p>h:
          return(n) 
        if (n%p)==0:
          break    
# Generate a random odd number n (2**k > n > 2**(k-1), k >= 2) with proveable
# primality employing Maurer's algorithm (the (k-1)-th bit of n is 1).
# Cf. sec.4.62 of HAC [1, p.153].

def provableprime(k):
  global ptab
  RANDOM=random.SystemRandom()
# The default size of ptab (see above) is sufficiently large for cases k<=20.
  if k<=20:
    while True:
# Select a random odd integer in the interval [2**(k-1), 2**k-1] (A. J. Menezes,
# personal communication).
      n=RANDOM.randint(2**(k-1),2**k-1)|1
      h=math.ceil(math.sqrt(n))
      for p in ptab[1:]:
        if p>h:
          return(n) 
        if (n%p)==0:
          break    
# We use c=0.005 which has been experimentally found to be optimal in processing
# time for common PC under MS Windows and values of k of practical interest.
# A different c value may be desirable for use in different computing
# environments.        
  c=0.005
  bb=math.ceil(c*k*k)
  checkptab(bb)
  m=20
  if k>2*m:
    while True:
      s=RANDOM.uniform(0,1)
      r=2**(s-1)
      if (k-r*k)>m:
        break
  else:
    r=0.5
  q=provableprime(math.floor(r*k)+1)
  ii=2**(k-1)//(2*q)
  success=0
  while success==0:
    rr=RANDOM.randint(ii+1,2*ii)    
    n=2*rr*q+1
    suc=1
    for p in ptab:
      if p>bb:
        break
      if (n%p)==0:
        suc=0
        break
    if suc==0:
      continue
# See [1, p.153, 4.6.3 (ii)], Miller-Rabin test is employed here for purposes of
# improvement of efficiency only.
    if millerrabin(n,1,1)==1:
      a=RANDOM.randint(2,n-2)
      if pow(a,n-1,n)==1:
        b=pow(a,2*rr,n)
        if gcd(b-1,n)==1:
          success=1          
  return(n)



################################################################################



# Installation of the software.

# Both communication partners have to download the same version 3x of Python
# from http://www.python.org. (Employing the same version of Python ensures
# against any potentially possible incompatibilities among different versions.)
# The present code can be stored in a file named e.g. provableprime.py and the
# examples given further below run in Python's GUI IDLE. (File --> Open to find
# and open the file, then in the window showing the code Run --> Run Module to
# run it. One could also type provableprime.py in a DOS-window.) Modifications
# of the code in the code window, e.g. the plaintext string, can be done online
# and the code re-run.



################################################################################
################################################################################
################### end of part 1 (of 4) of PROVABLEPRIME2.1 ###################PROVABLEPRIME2.1

################################################################################
################# begin of part 2 (of 4) of PROVABLEPRIME2.1 ###################



# Appendix.



# Example 1: Generation of a pseudo-random provable prime n of nb bits.

print("Illustrative example 1") 
print()

nb=1024
start=time.clock()
n=provableprime(nb)
print("Prime generation time %6.3f sec"%(time.clock()-start))
print() 

# Print n in hexadecimal format, excluding the prefix "0x". (Use print(hex(n))
# and print(n) to print n in hexadecimals with prefix and in decimals
# respectively.)

print("Prime generated (in hex format, excluding the prefix '0x'):")
print()
print(hex(n)[2:])
print()



# In order to demonstrate some potential practical usages of the function
# provableprime(), we'll employ it in the following to generate RSA keys and
# develop a couple of simple to understand schemes that perform encryption 
# (with authentication) as well as digital signature for sequences of fixed
# sized blocks and cryptologically secure pseudo-random bit generation,
# employing at their base RSA only in each case. We forgo the use of other
# cryptographical primitives than RSA (i.e. materials like hash functions are
# not involved) so as to reduce the complexity of the programming logic to a
# minimum for easy comprehension/verification and hence trust to use in practice
# by our targeted users, the common people. It may be noted that the schemes may
# be criticized for being inefficient (since anyway RSA is commonly used for
# efficiency reasons only to transmit keys for symmetric ciphers and not
# directly to encrypt proper messages as we do) or containing idiosyncracies of
# the present author (i.e. some design ideas in the illustrative Example 3, 4
# and 3S below are presumably his own). On the other hand, the first point is
# apparently unessential because "really" check_e_p=egcd(e,p-1)secret messages of our targeted users,
# the common people, are as a rule fairly short and the second point can be
# countered on the ground that our design concepts are anyway evidently secure,
# if RSA itself as such is considered to be secure. Time measurements are
# provided in all illustrative examples below, showing that the processing times
# are generally entirely acceptable.



# Example 2: Generation of RSA keys and their I/O to file storage of computers
# (assumed to be securely protected from clandestine access by the adversary!).


# maxmb: Plaintext to be processed by RSA is assumed to be in blocks of chosen
#        (constant) sizes up to a maximum value of maxmb bits, i.e. a list of
#        integers in [0,2**maxmb-1]. The generated modulus n=p*q has thus to
#        satisfy n > 2**maxmb. maxmb is required to be a multiple of 8 and >=
#        2048.
#
# pb: p of the modulus n has pb bits.
#
# qb: q of the modulus n has qb bits.
#
# trialnum: trialnum trials will be done such that n = p*q > 2**maxmb and a
#           number of security constraints are satisfied. If not successful, the
#           function aborts and another call of rsakeygeneration() has to be
#           made by the user. Choosing pb=maxmb//2, qb=pb+2 and trialnum=5 will
#           in general always lead to success. We pose constraints that are
#           partly more conservative than in [5], in particular both e and d are
#           required to be larger than the square root of n. In case of success
#           e, d, and n will be returned.
#
# [5] Algorithms, Key Sizes and Parameters Report, pp.30-31, ENISA 2013,
# available at http//www.enisa.europa.eu.

def rsakeygeneration(maxmb,pb,qb,trialnum):
  assert maxmb%8 ==0 and maxmb >= 2048
  RANDOM=random.SystemRandom()
  start=time.clock()
  for trial in range(trialnum):
    p=provableprime(pb)
    q=provableprime(qb)
    n=p*q
    if n < 2**maxmb or\
      not ((1 < abs(math.log2(p)-math.log2(q)) < 20) and
           (abs(p-q)**4 >= n)):
      continue
    phi=(p-1)*(q-1)
    while True:
      e=RANDOM.randint(0,phi-1) 
      if (e%2)!=0 and gcd(e,phi)==1 and e*e>n:
        d=modinv(e,phi)
        if d*d>n and d<phi:
          break
    print("RSA key generation: success  trials%3d  time %6.3f sec"\
          %(trial+1,time.clock()-start))
    return(e,d,n)
  print("RSA key generation: failure *********  trials%3d  time %6.3f sec"\
        %(trial+1,time.clock()-start))
  exit(111)


# Output integers e, d, and n to a file. File name is the string of the
# formal parameter name extended by "keyfile.bin".

def writekeyfile(name,e,d,n):
  f=open(name+"keyfile.bin","wb")
  pickle.dump([e,d,n],f)
  f.close()
  return


# The inverse of writekeyfile().

def readkeyfile(name):
  f=open(name+"keyfile.bin","rb")
  g=pickle.load(f)
  f.close()
  return(g[0],g[1],g[2])


print()
print("Illustrative example 2")
print()


# Bob and Alice both generate RSA keys, store them on their computers (assumed
# to be immune from attacks by the adversary) and let their public keys (e,n)
# be authentically known to each other. (We assume that for acquaintances this
# is not difficult to achieve. Within a small group of persons the authenticity
# could eventually also be established via certification with digital
# signatures of a CA, see Epilogue.) To print out RSA keys, cf. Example 1.

# For simplicity of our illustration examples, Bob and Alice both choose to
# employ the same value of maxmb in rsakeygeneration(). This is however not a
# necessary requirement for encryption of messages between them. What is
# required is that in invocaton of rsaencryptplaintexttoct() and
# rsadecryptcttoplaintext() as well as in invocation of
# rsaencryptbytearraytoct() and rsadecryptcttobytearray() further below the
# same value of mb is used. 


# Key generation of Bob.

maxmb=2200
pb=1100
qb=1102

bobpublice,bobsecretd,bobn=rsakeygeneration(maxmb,pb,qb,5)

writekeyfile("bob",bobpublice,bobsecretd,bobn)
print()

# Key generation of Alice.

maxmb=2200
pb=1100
qb=1102

alicepublice,alicesecretd,alicen=rsakeygeneration(maxmb,pb,qb,5)

writekeyfile("alice",alicepublice,alicesecretd,alicen)
print()



# The following ten auxiliary functions will be used or useful in situations of
# Example 3, 4 and 3S further below:


# Transformation of a character string to a list of integers within a given
# fixed bit-length mb, i.e. integers in [0, 2**mb-1].
#
# plaintextstring: The input text string coded in latin-1. It will be padded,
#                  if necessary, with filler characters to block boundary.
#
# fillerchar: A chosen special filler character to be used. This character is
#             assumed to have no occurrence in the given plaintextstring and
#             is not alphabetical.
#
# mb: See comments of rsakeygeneration().
#
# kn: 0: Padding first with one fillerchar and then with pseudo-randomly chosen
#        alphabetical characters.
#
#     1: Padding with all characters identical to fillerchar.
#
# (kn=0 will be used in Example 3 and 3S and kn=1 in Example 4.)

def plaintextstringtopt(plaintextstring,fillerchar,mb,kn):
  alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  assert mb%8 == 0 and fillerchar not in plaintextstring and\
         fillerchar not in alpha
  RANDOM=random.SystemRandom()
  lptstr=len(plaintextstring)
  bmb=mb//8
  q,r=divmod(lptstr,bmb)
  if r!=0:
    q+=1
    d=bmb-r
    if kn==0:
      plaintextstring+=fillerchar
      for i in range(0,d-1):
        plaintextstring+=RANDOM.choice(alpha)
    else:
      plaintextstring+=d*fillerchar    
  gg=bytearray(plaintextstring,'latin-1') 
  pt=[]
  k=0
  for i in range(q):
    h=0
    for j in range(bmb):
      h<<=8
      h|=gg[k+j]
    k+=bmb
    pt+=[h]
  return(pt)


# The inverse of plaintextstringtopt().

def pttoplaintextstring(pt,fillerchar,mb):
  assert mb%8 == 0
  bmb=mb//8
  plaintextstring=""
  ordfc=ord(fillerchar)
  lpt=len(pt)
  for i in range(lpt):
    kk=pt[i]
    hh=[]
    for j in range(bmb):
      hh.append(kk&255)
      kk>>=8
    hh.reverse()
    if i==lpt-1:
      if ordfc in hh:
        idx=hh.index(ordfc)
        hh=hh[:idx]
    for jj in hh:
      plaintextstring+=chr(jj)    
  return(plaintextstring)


# Output alist, a list of integers, to a file. File name is the string of the
# formal parameter listname extended by "list.bin".

def writelistfile(listname,alist):
  f=open(listname+"list.bin","wb")
  pickle.dump(alist,f)
  f.close()
  return


# The inverse of writelistfile()

def readlistfile(listname):
  f=open(listname+"list.bin","rb")
  alist=pickle.load(f)
  f.close()
  return(alist)


# Output astring, a text string, to a file. File name is the string of the
# formal parameter stringname extended by "string.txt".

def writestringfile(stringname,astring):
  f=open(stringname+"string.txt","w")
  f.write(astring)
  f.close()
  return


# The inverse of writestringfile().

def readstringfile(stringname):
  f=open(stringname+"string.txt","r")
  astring=f.read()
  f.close()
  return(astring)


# Write a byte sequence to a binary file.

def writebinaryfile(byarray,binaryfilename):
  fp=open(binaryfilename+".bin","wb")
  fp.write(byarray)
  fp.close()


# The inverse of writebinaryfile().

def readbinaryfile(binaryfilename):
  fp=open(binaryfilename+".bin","rb")
  byarray=bytearray(fp.read())
  fp.close()
  return(byarray)


# Convert a byte sequence to pt. (For pt, see encrypttoct().) Length of byte
# sequence must be a multiple of mb//8.

def bytearraytopt(byarray,mb):
  assert mb%8 == 0
  bmb=mb//8
  lbyarray=len(byarray)
  assert lbyarray%bmb == 0
  pt=[]
  k=0
  while k < lbyarray:
    k1=k+bmb
    bb=byarray[k:k1]
    h=0
    for j in range(bmb):
      h<<=8
      h|=bb[j]
    pt+=[h]
    k=k1
  return(pt)


# The inverse of bytearraytopt().

def pttobytearray(pt,mb):
  assert mb%8 == 0
  bmb=mb//8
  lpt=len(pt)
  byarray=bytearray(0)
  for i in range(lpt):
    kk=pt[i]
    hh=bytearray(0)
    for j in range(bmb):
      hh+=bytearray([kk&255])
      kk>>=8
    hh.reverse()
    byarray+=hh 
  return(byarray)



# Example 3: RSA block encryption processing with authentication (integrity
# check).


# As indicated in Prologue, this is an implementation of an idea of the present
# author to closely combine asymmetric and symmetric encryptions, which
# presumably is novel.
#
# Encryption will be done with receiver's public key on blocks chained in a way
# analogous to the chaining in common symmetric block encryption processing. The
# chaining value is initialized by a pseudo-random iv. A plaintext block (as a
# big integer resulting from character to integer transformation) is xor-ed with
# the chaining value before being encrypted. The chaining value is then updated
# by xor-ing it with the current plaintext block and the ciphertext block. (In
# distinction to the well-known CBC chaining, we empoly thus PCBC chaining. Note
# that the variable chaining sums up via xoring the values of pp and cc of all
# preceding blocks such that it has a in this context very desirable high error
# propagation property. The iv and the last chaining value obtained are then
# encrypted and appended to ct, the list of the ciphertext blocks, for purposes
# of authentication (integrity check). It is to be particularly remarked that we
# have, as described, integrated certain well-known techniqes commonly employed
# in symmetric block encryption into asymmetric encryption. A normal message is
# processed in this example. In its place there could of course be anything else
# instead, e.g. a secret key for use in a symmetric block cipher (which is how
# RSA is commonly used in other software).
#
# Users employ for encryption and decryption the functions
# rsaencryptplaintexttoct() and rsadecryptcttoplaintext() respectively in case
# the given secret material is in form of a text string, and the functions
# rsaencryptbytearraytoct() and rsadecryptcttobytearray() respectively in case
# the given secret material is in form of a byte sequence.


# Encrypt pt, a list of integers of mb bits (integers in [0, 2**mb-1]) to ct,
# another list of integers, with the public key of the receiver. Note that ct
# returned is a list of integers which may be larger than mb bits, i.e. up to
# receivern-1.
#
# mb: See comments of rsakeygeneration(). 
#
# (receivere, receivern): The public key of the receiver. 

def encrypttoct(pt,mb,receivere,receivern):
  assert mb%8 ==0 and mb >= 2048 and 2**mb < receivern
  tpmb=2**mb
  tpmbn1=tpmb-1
  RANDOM=random.SystemRandom()
# A pseudo-random iv is generated to be the initial chaining value.
  iv=RANDOM.randint(1,tpmb-1)
  chaining=iv
  ct=[]
# Each pp is a block of plaintext.
  for pp in pt:
    assert pp < tpmb
    u=chaining^pp
# Encrypt with receiver's public key to obtain the ciphertext block.
    cc=pow(u,receivere,receivern)
    ct.append(cc)
# Update the chaining value by xor-ing it with the plaintext block and the
# ciphertext block (limited to mb bits).
    chaining^=pp^(cc&tpmbn1)
# Here at the end of the loop the chaining has its last value.
# Encrypt iv and the last chaining value and put them into ct.
  g=pow(iv,receivere,receivern)
  h=pow(chaining,receivere,receivern)
  ct+=[g,h]
  return(ct)


# The inverse of encrypttoct().

def decryptcttopt(ct,mb,receiverd,receivern):
  assert mb%8 ==0 and mb >= 2048 and 2**mb < receivern
  tpmb=2**mb
  tpmbn1=tpmb-1
  g=ct[-2]
  iv=pow(g,receiverd,receivern)
  chaining=iv
  pt=[]
  for cc in ct[:-2]:
    u=pow(cc,receiverd,receivern)
    pp=chaining^u
    pt.append(pp)
    chaining^=pp^(cc&tpmbn1)
  h=ct[-1]
  chainingcheck=pow(h,receiverd,receivern)
  if chainingcheck==chaining:
    print("Authentication (integrity check) o.k.")
  else:
    print("Authentication (integrity check) failed #########")
    exit(222)
  return(pt)


# Encrypt a plaintext string to ct, a list of integers, with the public key of
# the receiver.
#
# plaintextstring: The text string coded in in latin-1 to be encrypted. It will
#                  be padded, if necessary, with filler characters to block
#                  boundary.
#
# fillerchar: A (non-secret) special filler character to be used in the
#             processing. This character is assumed to have no occurrence in the
#             given plaintextstring and is not alphabetical. 
#
# mb: See comments of rsakeygeneration().
#
# (receiverpublice, receivern): The public key of the receiver.
#
# Note that ct returned is a list of integers which may be larger than mb bits.

def rsaencryptplaintexttoct(plaintextstring,fillerchar,mb,
                            receiverpublice,receivern):
  assert 2**mb < receivern
  pt=plaintextstringtopt(plaintextstring,fillerchar,mb,0)
  ct=encrypttoct(pt,mb,receiverpublice,receivern)
  return(ct)


# The inverse of rsaencrpytplaintexttoct(). Note that mb and fillerchar must
# have the same values as employed by the sender in rsaencrpytplaintexttoct().

def rsadecryptcttoplaintext(ct,fillerchar,mb,receiversecretd,receivern):
  assert 2**mb < receivern
  pt=decryptcttopt(ct,mb,receiversecretd,receivern)  
  plainteststring=pttoplaintextstring(pt,fillerchar,mb)
  return(plaintextstring)


# Encrypt a byte sequence to ct, a list of integers, with the public key of
# the receiver.
#
# byarray: The byte sequence to be encrypted. Its length must be a multiple of
# mb//8. Padding would be necessay when this condition is not fulfilled, which
# could occur e.g. in case the result of a symmetric encryption is to be
# further processed by the present software (i.e. multiple encryption). The
# number of the arbitrary padding bytes need somehow be known by the receiver in
# order to discard them after RSA decryption.
#
# mb: See comments of rsakeygeneration().
#
# (receiverpublice, receivern): The public key of the receiver.
#
# Note that ct returned is a list of integers which may be larger than mb bits.

def rsaencryptbytearraytoct(byarray,mb,receiverpublice,receivern):
  assert 2**mb < receivern
  pt=bytearraytopt(byarray,mb)
  ct=encrypttoct(pt,mb,receiverpublice,receivern)
  return(ct)


# The inverse of rsaencryptbytearraytoct(). Note that mb must have the same
# value as employed by the sender in rsaencryptbytearraytoct().

def rsadecryptcttobytearray(ct,mb,receiversecretd,receivern):
  assert 2**mb < receivern
  pt=decryptcttopt(ct,mb,receiversecretd,receivern)
  byarray=pttobytearray(pt,mb)
  return(byarray)


print() 
print("Illustrative example 3")
print()


# Bob uses the public key of Alice that is authentically known to him to encrypt
# the plaintextstring to a list of integers ct, writes ct to a file and sends
# the file to Alice. (plaintextstring could be written to or read from a file
# with writestringfile() and readstringfile(). ct, a list of integers, could,
# if necessary, otherwise be printed out in the Python window with print(ct),
# cut and paste with the mouse and sent directly as normal text via email to be
# assigned by Alice to a variable ct to perform decryption.) (For the present
# run, values of Alice's public key are available to the system from Example 2.)

plaintextstring=\
"The problem of distinuishing prime numbers from composites and of resolving "\
"composite numers into their prime factors, is one of the most important and "\
"useful in all of arithmetic. ... The dignity of science seems to demand "\
"that every aid to the solution of such an elegant and celebrated problem be "\
"zealously cultivated. -- C. F. Gauss, Disquisitiones Arithmeticae, Article "\
"329 (1801)."

fillerchar="#"
mb=2200

start=time.clock()
ct=rsaencryptplaintexttoct(plaintextstring,fillerchar,mb,alicepublice,alicen)
print("Encryption time %6.3f sec"%(time.clock()-start))
print()
writelistfile("bobct",ct)


# Alice retrieves her keys from a file on her computer, read in the list of
# integers ct from the file obtained from Bob and decrypts ct with her secret
# key to a plaintextstring1 that is verified for authentication (integrity
# check).

alicepublice,alicesecretd,alicen=readkeyfile("alice")

ct=readlistfile("bobct")

fillerchar="#"
mb=2200

stat=time.clock()
plaintextstring1=rsadecryptcttoplaintext(ct,fillerchar,mb,alicesecretd,alicen)
print("Decryption time %6.3f sec"%(time.clock()-start))
print()

print("Message received:")
print()
print(plaintextstring1)
print()



################################################################################
################### end of part 2 (of 4) of PROVABLEPRIME2.1 ###################

################################################################################
################# begin of part 3 (of 4) of PROVABLEPRIME2.1 ###################

# Example 4: RSA digital signature processing.


# Document signing is performed via first processing the text string of the
# given document as if it were to be encrypted with signer's own public key in
# a manner fairly analogous to rsaencryptplaintexttoct(), thereby resulting in
# an iv and a last chaining value. Both values are then signed with signer's
# secret key to form a list of two integers that serves as the signer's
# signature of the document. (Note that the signature, a list of two integers,
# could be written to or read from a file, employing writelistfile() and
# readlistfile(), if desired, cf. Example 3. The documenttextstring could be
# written to or read from a file with writestringfile() and readstringfile().) 
#
# It may be remarked that, similar to Example 3, the idea underlying our scheme
# differs from what is conventionally done in digital signature processing and
# is presumably novel.


# documenttextstring: The input document string coded in latin-1.
#
# fillerchar: A (non-secret) special filler character to be used in the
#             processing. This character is assumed to have no occurrence in the
#             given plaintextstring.
#
# mb: See comments of rsakeygeneration().
#
# (signerpublice, signersecretd, signern): The public and secret keys of the
#                                          signer.
#
# Note that the returned signature of the signer is a list of two integers which
# may be larger than mb bits.

def rsasigndocument(documenttextstring,fillerchar,mb,
                    signerpublice,signersecretd,signern):
  assert mb%8 ==0 and mb >= 2048 and 2**mb < signern
  tpmb=2**mb
  tpmbn1=tpmb-1
# Note that padding is done here with characters that are all identical to
# fillerchar.
  pt=plaintextstringtopt(documenttextstring,fillerchar,mb,1)
  RANDOM=random.SystemRandom()
  iv=RANDOM.randint(1,tpmb-1)
  chaining=iv  
  for pp in pt:
    assert pp < tpmb
    u=chaining^pp
# Encrypt with signer's public key to obtain the ciphertext block.
    cc=pow(u,signerpublice,signern)
# Update the chaining value by xor-ing it with the plaintext block and the
# ciphertext block (limited to mb bits).
    chaining^=pp^(cc&tpmbn1)
# Here at the end of the loop the chaining has its last value.
# Sign the iv with signer's secret key.
  g=pow(iv,signersecretd,signern)
# Sign the last chaining value with signer's secret key.
  h=pow(chaining,signersecretd,signern)
# Signature is the list consisting of g and h. 
  signature=[g,h]
  return(signature)


# The signature accompanying a documenttextstring is checked with the public
# key of the signer. Note that mb and fillerchar must have the same values as
# employed by the signer in rsasigndocument().

def rsachecksignature(documenttextstring,signature,fillerchar,mb,
                      signerpublice,signern):
  assert mb%8 ==0 and mb >= 2048 and 2**mb < signern
  tpmb=2**mb
  tpmbn1=tpmb-1
  pt=plaintextstringtopt(documenttextstring,fillerchar,mb,1)
  g=signature[0]
# Obtain iv from the signed iv through using signer's public key.
  iv=pow(g,signerpublice,signern)
  chaining=iv
  for pp in pt:
    u=chaining^pp
# Encrypt with signer's public key (same as done in rsasigndocument()).
    cc=pow(u,signerpublice,signern)
    chaining^=pp^(cc&tpmbn1)
# Here at the end of the loop the chaining has its last value.
# Obtain the last chaining value previously obtained by signer from its signed
# value through using his public key.
  h=signature[1]
  chainingcheck=pow(h,signerpublice,signern)
# Check equality of the two chaining values.
  if chainingcheck==chaining:
    print("Signature check o.k.")
  else:
    print("Signature check failed #########")
  return


print()
print("Illustrative example 4")
print()


# Bob retrieves his keys from a file on his computer and with these signs a
# given document. His signature accompanies then the given document. (See also
# comments at the beginning of this Example.)

documenttextstring=\
"Everyone has the right to freedom of opinion and expression; this right "\
"includes freedom to hold opinions without interference and to seek, receive "\
"and impart information and ideas through any media and regardless of "\
"frontiers. -- The Universal Declaration of Human Rights, United Nations, "\
"Article 19."

print("Document to be signed:")
print()
print(documenttextstring)
print()

bobpublice,bobsecretd,bobn=readkeyfile("bob")

fillerchar="#"
mb=2200

start=time.clock()
signature=rsasigndocument(documenttextstring,fillerchar,mb,
                          bobpublice,bobsecretd,bobn)
print("Signature signing time %6.3f sec"%(time.clock()-start))
print()


# Any person possessing the document and the signature can verify that Bob has
# signed the documenet by using the public key of Bob that is known to him as
# follows. (For the present run, values of Bob's public key are available to the
# system from Example 2.)

fillerchar="#"
mb=2200

start=time.clock()
rsachecksignature(documenttextstring,signature,fillerchar,mb,
                  bobpublice,bobn)
print("Signature verification time %6.3f sec"%(time.clock()-start))
print()



# Example 3S: RSA block encryption processing with authenticaion (integrity
# check) and signature of the sender.


# This is a successful integration of our ideas of Exmaple 3 and Example 4, the
# significance of which for our targeted users should be self-evident, since it
# is the normal case that both communication partners possess RSA keys. The iv
# and the last chaining value of encryption processing are signed with sender's
# secret key before being encrypted with receiver's public key.
#
# For the purposes of the functions, cf. the corresponding functions of
# Example 3.


def encryptptoctsigned(pt,mb,receivere,receivern,senderd,sendern):
  assert mb%8 ==0 and mb >= 2048 and 2**mb < receivern and 2**mb < sendern
#
# An integer item of mb bits will be signed with sender's secret key and the
# result (which may be larger than mb bits) separated into segments of mb bits
# to be encrypted by receiver's public key. The result returned is a list of
# integers slist. This function is used to process iv and chaining further
# below.
  def signitemandencrypt(item):
    if item==0:
      return([0])
    w=2**mb
    q=pow(item,senderd,sendern)
    slist=[]
    while q!=0:
      q,r=divmod(q,w)
      slist.append(pow(r,receivere,receivern))
    return(slist)
#
  tpmb=2**mb
  tpmbn1=tpmb-1
  RANDOM=random.SystemRandom()
# A pseudo-random iv is generated to be the initial chaining value.
  iv=RANDOM.randint(1,tpmb-1)
  chaining=iv
  ct=[]
# Each pp is a block of plaintext.
  for pp in pt:
    assert pp < tpmb
    u=chaining^pp                    
# Encrypt with receiver's public key to obtain the ciphertext block.
    cc=pow(u,receivere,receivern)
    ct.append(cc)
# Update the chaining value by xor-ing it with the plaintext block and the
# ciphertext block (limited to mb bits).
    chaining^=pp^(cc&tpmbn1)
# Here at the end of the loop the chaining has its last value.
# Sign and encrypt iv and the last chaining value with signitemandencrypt() to
# lists and put them into ct.
  glist=signitemandencrypt(iv)
  hlist=signitemandencrypt(chaining)
  ct.append(glist)
  ct.append(hlist)
  return(ct)


# The inverse of encrypttoctsigned().

def decryptcttoptsigned(ct,mb,receiverd,receivern,sendere,sendern):
  assert mb%8 ==0 and mb >= 2048 and 2**mb < receivern and 2**mb < sendern
#
# The inverse of signitemandencrypt() of encryptptoctsigned().
  def decryptsigneditemlist(slist):
    lslist=len(slist)
    q=0
    for i in range(lslist-1,-1,-1):
      q<<=mb
      q|=pow(slist[i],receiverd,receivern)
    item=pow(q,sendere,sendern)
    return(item)
#
  tpmb=2**mb
  tpmbn1=tpmb-1
  glist=ct[-2]
  iv=decryptsigneditemlist(glist)
  chaining=iv
  pt=[]
  for cc in ct[:-2]:
    u=pow(cc,receiverd,receivern)
    pp=chaining^u
    pt.append(pp)
    chaining^=pp^(cc&tpmbn1)
  hlist=ct[-1]
  chainingcheck=decryptsigneditemlist(hlist)
  if chainingcheck==chaining:
    print("Signature and Authentication (integrity check) o.k.")
  else:
    print("Signature and/or Authentication (integrity check) failed #########")
    exit(222)
  return(pt)


def rsaencryptplaintexttoctsigned(plaintextstring,fillerchar,mb,
    receiverpublice,receivern,sendersecretd,sendern):
  assert 2**mb < receivern and 2**mb < sendern
  pt=plaintextstringtopt(plaintextstring,fillerchar,mb,0)
  ct=encryptptoctsigned(pt,mb,receiverpublice,receivern,
                        sendersecretd,sendern) 
  return(ct)


# The inverse of rsaencrpytplaintexttoctsigned(). Note that mb and fillerchar
# must have the same values as employed by the sender in
# rsaencrpytplaintexttoctsigned().

def rsadecryptcttoplaintextsigned(ct,fillerchar,mb,
    receiversecretd,receivern,senderpublice,sendern):
  assert 2**mb < receivern and 2**mb < sendern
  pt=decryptcttoptsigned(ct,mb,receiversecretd,receivern,
                         senderpublice,sendern)  
  plainteststring=pttoplaintextstring(pt,fillerchar,mb)
  return(plaintextstring)


def rsaencryptbytearraytoctsigned(byarray,mb,receiverpublice,receivern,
                                  sendersecretd,sendern):
  assert 2**mb < receivern and 2**mb < sendern
  pt=bytearraytopt(byarray,mb)
  ct=encryptptoctsigned(pt,mb,receiverpublice,receivern,
                        sendersecretd,sendern) 
  return(ct)


# The inverse of rsaencryptbytearraytoctsigned(). Note that mb must have the
# same value as employed by the sender in rsaencryptbytearraytoctsigned().

def rsadecryptcttobytearraysigned(ct,mb,receiversecretd,receivern,
                                  senderpublice,sendern):
  assert 2**mb < receivern and 2**mb < sendern
  pt=decryptcttoptsigned(ct,mb,receiversecretd,receivern,
                         senderpublice,sendern)
  byarray=pttobytearray(pt,mb)
  return(byarray)



print() 
print("Illustrative example 3S")
print()


# Bob retrieves his keys from a file on his computer for signing purposes. He
# uses the public key of Alice that is authentically known to him to encrypt the
# plaintextstring to a list of integers ct, writes ct to a file and sends the
# file to Alice. (plaintextstring could be written to or read from a file with
# writestringfile() and readstringfile(). ct, a list of integers (containing at
# the end two lists of integers), could, if necessary, otherwise be printed out
# in the Python window with print(ct), cut and paste with the mouse and sent
# directly as normal text via email to be assigned by Alice to a variable ct to
# perform decryption.) (For the present run, values of Alice's public key are
# available to the system from Example 2.)

bobpublice,bobsecretd,bobn=readkeyfile("bob")

# We employ the same plain text as in Example 3.

plaintextstring=\
"The problem of distinuishing prime numbers from composites and of resolving "\
"composite numers into their prime factors, is one of the most important and "\
"useful in all of arithmetic. ... The dignity of science seems to demand "\
"that every aid to the solution of such an elegant and celebrated problem be "\
"zealously cultivated. -- C. F. Gauss, Disquisitiones Arithmeticae, Article "\
"329 (1801)."

fillerchar="#"
mb=2200

start=time.clock()
ct=rsaencryptplaintexttoctsigned(plaintextstring,fillerchar,mb,
                                 alicepublice,alicen,bobsecretd,bobn)
print("Encryption time %6.3f sec"%(time.clock()-start))
print()
writelistfile("bobct",ct)


# Alice retrieves her keys from a file on her computer, read in the list of
# integers ct from the file obtained from Bob and decrypts ct with her secret
# key to a plaintextstring1 that is verified for authentication (integrity
# check). Bob's public key involved in the processing of his signature is
# authentically known to her. (For the present run, values of Bob's public key
# are available to the system from Example 2.)

alicepublice,alicesecretd,alicen=readkeyfile("alice")

ct=readlistfile("bobct")

fillerchar="#"
mb=2200

stat=time.clock()
plaintextstring1=\
  rsadecryptcttoplaintextsigned(ct,fillerchar,mb,
                                alicesecretd,alicen,bobpublice,bobn)
print("Decryption time %6.3f sec"%(time.clock()-start))
print()

print("Message received:")
print()
print(plaintextstring1)
print()



# Example 5: RSA pseudo-random bit generation.


# With a RSA PRBG generate a sequence of bits of desired length.
#
# While for purpose of encryption e and n are commonly public and not kept
# secret, the situation is here different. Since for obtaining acceptable
# efficiency in generating the bit sequence we shall use e=3 (using a rather
# large n is comparatively less critical in speed), an adversary knowing n in
# the present context would mean that he has the same PRBG as the user (he may
# not know the seed, though). On the other hand, commonly for this application
# n need not be kept by the user and can be discarded, once the bit sequence
# has been obtained.


# Generate a modulus of a RSA PRBG for e=3. See [1, p.185, 291].
#
# mb: The modulus of PRBG, rsaprbgn, is required to satisfy rsaprbgn > 2**mb
#     and be a multiple of 8 and >= 2048.
#
# pb: p of the modulus n has pb bits.
#
# qb: q of the modulus n has qb bits.
#
# trialnum: trialnum trials will be done such that n = p*q > 2**mb and a number
#           of security constraints are satisfied. If not successful, the
#           function aborts and another call of rsaprbgmodulusgeneration() has
#           to be made by the user. Choosing pb=mb//2, qb=pb+2 and trialnum=5
#           will in general always lead to success. We choose to pose some of
#           the contraints employed in rsakeygeneration(). 

def rsaprbgmodulusgeneration(mb,pb,qb,trialnum):
  assert mb%8 ==0 and mb >= 2048
  start=time.clock()
  for trial in range(trialnum):
    while True:
      p=provableprime(pb)
      if (p-1)%3 != 0:
        break
    while True:
      q=provableprime(qb)
      if (q-1)%3 != 0:
        break
    rsaprbgn=p*q
    phi=(p-1)*(q-1)
    if rsaprbgn<2**mb or gcd(3,phi)!=1 or\
      not ((1 < abs(math.log2(p)-math.log2(q)) < 20) and
           (abs(p-q)**4 >= rsaprbgn)):
      continue
    print("RSA PRBG modulus generation: success  trials%3d  time %6.3f sec"\
          %(trial+1,time.clock()-start))  
    return(rsaprbgn)
  print("RSA PRBG modulus generation: failure *********  trials%3d  time \
        %6.3f sec"%(trial+1,time.clock()-start)) 
  exit(333)


# Generate a bit sequence of length nbits, employing the modulus rsaprbgn and
# a pseudo-random seed. Returned values are a pseudo-random number prnumber and
# its corresonding bit sequence of length nbits (leading 0's are included).
# See [1, p.185].

def rsaprbggenbits(rsaprbgn,nbits):
  RANDOM=random.SystemRandom()
  while True:    
    rsaprbgseed=RANDOM.randint(1,rsaprbgn-1)
    if gcd(rsaprbgseed,rsaprbgn)==1:
      break
  bitstr=""
  count=0
  while count<nbits:
    rsaprbgseed=pow(rsaprbgseed,3)%rsaprbgn
    bitstr+=str(rsaprbgseed&1)
    count+=1
  prnumber=eval("0b"+bitstr)
  return(prnumber,bitstr)


print()
print("Illustrative example 5")
print()


mb=2800
pb=1400
qb=1402
nbits=500

rsaprbgn=rsaprbgmodulusgeneration(mb,pb,qb,5)
print()

start=time.clock()
prnumber,bitstr=rsaprbggenbits(rsaprbgn,nbits)
print("Bit sequence generated:")
print()
print(bitstr)
print("Bit sequence generation time %6.3f sec"%(time.clock()-start))
print()



################################################################################



# Users who are new to Python or who begin to use a downloaded new version of
# the Python software may like to know a bit about the statistical qualities of
# the random numbers generated with the class SystemRandom which we employ in
# PROVABLEPRIME. The following code is intended to serve for that purpose.
# prnbitn is the number of bits of the PRNs to be generated and must be a
# multiple of 8. 


# Maurer's Universal Test, see [6].
#
# [6] J-S. Coron, D. Naccache, An Accurate Evaluation of Maurer's Universal Test.
#     http://www.jscoron.fr/publications/universal.pdf


qq=2560
qqp1=qq+1
kk=256000
qqkkp1=qq+kk+1


def maurertest(bb):
  global qq,qqp1,kk,qqkkp1
  eftu=7.1836656
# y1 and y2 are for rho=0.01 and rho=0.001 respectively.
  y1=2.5758
  y2=3.2905
  t=[0 for i in range(256)]
  for i in range(1,qqp1,1):
    t[bb[i]]=i
  sum=0.0
  for i in range(qqp1,qqkkp1,1):
    sum+=math.log10(i-t[bb[i]])
    t[bb[i]]=i
  tu=(sum/kk)/math.log10(2.0)
  c=math.sqrt(0.3732189+(0.3730195*256)/kk)
  sigma=c*math.sqrt(3.2386622/kk)
  t11=eftu-y1*sigma
  t12=eftu+y1*sigma
  t21=eftu-y2*sigma
  t22=eftu+y2*sigma
  return(tu,t11,t12,t21,t22)


def maurertestresult(h,gg):
  global chnum
  global qq,qqp1,kk,qqkkp1
  if h*chnum<qqkkp1:
    print("Error in maurertestresult")
    exit(6)
  bb=[0 for k in range(h*chnum)]
  u=0
  k1=-1
  k2=chnum-1
  for i in range(h):
    g=gg[i]
    for k in range(k2,k1,-1):
      bb[u]=g&0xff
      g>>=8
      u+=1
    k1+=chnum
    k2+=chnum
  tu,t11,t12,t21,t22 = maurertest(bb)
  print("Maurer's Universal Test for L=8, rho=0.01 (Middle value is the "\
        "test statistic\nand should lie between the other two values): "\
        "%6.3f %6.3f %6.3f"%(t11,tu,t12))


def randtest(prnbitn):
  global chnum
  if prnbitn<8 or (prnbitn%8)!=0:
    print("Error randtext: Wrong prnbitn")
    exit(55555)
  chnum=prnbitn//8
  h=qqkkp1//chnum
  if h*chnum<qqkkp1:
    h+=1
  RANDOM=random.SystemRandom()
  tpwbitnm1=2**prnbitn-1
  print("PRNs generated with RANDOM.randint():")
  gg=[RANDOM.randint(0,tpwbitnm1) for i in range(h)]  
  maurertestresult(h,gg)
  print()
  print("PRNs generated with RANDOM.getrandbits():")
  gg=[RANDOM.getrandbits(prnbitn) for i in range(h)]
  maurertestresult(h,gg)
  return


# Example of user chosen test parameter:

prnbitn=128

print()
print("Test of Python's class SystemRandom, parameter used:")
print("prnbitn:",prnbitn)
print()
randtest(prnbitn)



################################################################################



# Epilogue.


# We presume that the computer, on which this software is run, is free from
# malware infection via software and/or hardware means and that there are no
# emission security risks (which could be manifold in practical situations).
# cf. e.g. http://arxiv.org/abs/1407.2029,
# https://www.vusec.net/projects/flip-feng-shui/,
# http://www.jammed.com/~jwa/tempest.html and 
# https://de.wikipedia.org/wiki/Van-Eck-Phreaking

# Note that, since for random number generation we employ Python's SystemRandom
# class (which uses sources provided by the operating system via os.urandom())
# in the function provableprime() and elsewhere, the prime obtained in Example
# 1 and the RSA keys generated and the iv's employed in Examples 2, 3, 4 and 3S
# as well as the modulus and the seed used in Example 5 are different in
# different runs of this code and consequently the resulting ciphertext in
# Example 3 and 3S (not printed out), the digital signature in Example 4 (not
# printed out) and the bit sequence in Example 5 are also different in different
# runs. All this is what it should be.

# For a discussion of security of RSA, see [1, p.287, 7].
#
# [7] M. J. Hinek, Cryptanalysis of RSA and its Variants, 2010.

# For conversion of byte sequence to hex string and vice versa, the utility
# functions byarraytohexstr() and hexstrtobyarray() in author's RANDOMPREFIX
# (see URL further below) could be useful.

# The functions doing I/O to files could be easily modified for storage on
# external devices (with corresponding care being taken against clandestine
# access by the adversary!) Note that readkeyfile(), writekeyfile() and
# readlistfile(), writelistfile() are special cases of readbinaryfile(),
# writebinaryfile() so that files that are written out with writekeyfile() and
# writelistfile() could later, if needed, also be handled with readbinaryfile()
# and writebinaryfile(), using the appropriate parameter values.

# It should be noted that RSA keys generated (Example 2) for a given value of
# maxmb could be used for applications (Example 3, 4 and 3S) of eventually lower
# values of mb. For what is required is only that the modulus n of the keys be
# larger than 2**mb. Using a modulus n much larger than necessary translates
# albeit to a larger computation time of the applications. We require mb >= 2048
# and be a multiple of 8 but otherwise mb can be entirely arbitrarily chosen by
# the user, e.g. 2104.

# For Example 3 and 3S more sophisticated updating of the chaining value is
# conceivable, e.g. chaining^=f(pp,cc), with f(x,y)=2xy+x+y mod tpmb, but is
# deemed unnecessary.

# For symmetric encryption, only persons possessing (including of course
# eventually those "illegally" obtaining) the secret key could send encrypted
# messages that can be (properly, meaningfully) decrypted by the receiver. For
# asymmetric encryption, by nature of the system anyone could send a meaningful
# encrypted message to the receiver. Thus, unless additionally signed as done in
# Example 3S, "spams" couldn't be excluded from the very beginning. On the other
# hand, communication partners generally also have other communication channels,
# commonly a voice channel i.e. phone, which, even though not employed to
# transmit encrypted stuffs, could be utilized to plausibly check the genuinely
# sent meterials, e.g. via verifying the characters at a couple of arbitrarily
# randomly chosen positions of a message sent. The sender could also utilize a
# secret keyword/sequence agreed upon with the receiver and embed it in a
# certain location of his messages to serve as identification. (This secret
# evidently has to be appropriately guarded.) In case of multiple encryption
# with a symmetric cipher, i.e. the message processed by RSA contains a part
# that is the encryption by a symmetric cipher, the authenticity of the sender
# is of course given simply by the fact that the sender of a readable plaintext
# must be in possession of the proper secret key of the symmetric cipher and is
# hence genuine, unless that key were compromised. (We caution that a voice
# channel in extreme cases could eventually also be risky, cf.
# http://mashable.com/2016/03/20/face-tracking-software/#WfhDDpyVGuqu)

# It may be remarked that, in order to avoid the risk of replay attacks,
# digitally signed messages may need to contain stuffs e.g. reference numbers of
# sender and/or receiver, time and message serial numbers etc. so as to render
# the context of the messages unique and unambiguous.

# Note on the other hand that the fact that anyone could send encrypted messages
# to the owner of a RSA public key could be valuable in cases e.g. activists in
# non-democratic countries send (if they manage to anonymously send, eventually
# from an Internet cafe etc.) encrypted messages to the press in democratic
# foreign countries containing informations that, for some reasons, should not
# be immediately revealed to the public, nor known to any third parties. The
# press might prefer obtaining such anonymous encrypted messages. The public key
# is simply announced in the media, i.e. constantly published in the newspapers
# or journals.

# The proprietary information security software, with only illegible binaries
# available to the users, have understandably considerably high risks of being
# susceptible to manipulations by the secret agencies, which could not be
# ignored by any security-conscious users (at least after the spectacular
# revelations by Snowden and other activists). On the other hand, open-source
# PKI packages are generally very huge and also defacto impossible to be
# examined for correctness by persons without certain special expertise and/or
# sufficient time. The recent story of the Heartbleed Bug and Shellshock Bug
# have surprisingly and vividly shown the vulnerabilities of such software to
# the public. Thus, in order to securely protect oneself against the universal
# surveillance, a common user has (among the necessary countermeasures) either
# to implement all needed information security software himself or else
# carefully select available open-source codes that are simple and clear enough
# to be easily understood and verified by him to be ok. It is the present
# author's hope that the entire coding in this document well satisfies the
# latter criterion. (cf. also the last paragraph below for feasiblity of
# embedding a certain type of backdoors into proprietary RSA software.)

# If a sufficiently small number of persons can well trust a particular one of
# them, e.g. the project leader of a project team, this person could under
# circumstances properly function as a certification authority (CA), assuming of
# course that everyone of the group knows the genuine public key of this person.
# (He may, for the (less frequently required) certification purposes, also
# conveniently choose to use a larger key size than the team members who employ
# public key to encrypt less long-time secret materials as in our Example 3 and
# 3S above.) Otherwise, in any broader context, trusting CAs, which as a rule
################################################################################
################### end of part 3 (of 4) of PROVABLEPRIME2.1 ###################

################################################################################
################# begin of part 4 (of 4) of PROVABLEPRIME2.1 ###################

# are run by persons "totally" foreign to the users, is a source of extremely
# high risks that coexist with the software risks mentioned above. (There are
# of course also many other types of security risks, see [7]. That in general
# the diverse hardware components involved in communications are susceptible
# to manipulations, both during manufacture and afterwards, analogously to the
# software components, is easily comprehensible, though apparently less
# frequently discussed in the public.) Thus digital signatures that are commonly
# employed on the Internet, being dependent on the work of such CAs, are
# entirely insecure and consequently cannot be trusted at all. Some more words
# of the present author on this topic may be found in
# http://s13.zetaboards.com/Crypto/topic/7204526/1/. For issues of SSL, see
# http://queue.acm.org/detail.cfm?id=2673311. It appears plausible that
# in the pre-digital era comparable trusts on foreign persons, at least in
# highly critical personal issues, were absent. The present-day common trusts on
# the CAs -- many people even are not aware that such trusts are "implicitly"
# involved in general in communications on the Internet -- have apparently
# non-trivially contributed to the success of universal surveillance. On the
# other hand, PKI have certainly brought big money to some businessmen of that
# particular branch of commerce. In fact, one reads in [8, 19.5.3] the following
# extremely clear and definite statements more than a decade ago which appear
# albeit very deplorably to have even today not yet received the proper
# attention of the general public that they highly deserve:
#
# "In short, while public key infrastructures can be useful in some
# applications, they are unlikely to be the universal solution to security
# problems as their advocates seem to believe. They don't tackle most of the
# really important issues at all."
#
# [8] R. Anderson, Security Engineering, Wiley, 2001. This book has plenty of
# valuable informations, e.g. on emission security.

# The present author has recently endeavoured to recall the above decade-old
# quotation to a few Internet crypto forums, obtaining however only marginal
# echos. In one of his posts he even suggested that it would be desirable to
# have in all places where PKI is involved a warning to the common people
# similar to what one sees on the packages of cigarettes since some years. Note
# that in both cases there are similar essential monetary interests of the
# commercial firms involved and hence conceivably similar efforts to praise
# their products on the one hand and to suppress as far as possible the facts
# and opinions undesirable for them on the other hand. Manipulations of public
# opinions are understandably also among the general activities of the
# surveillance agencies [9], which at least partly explains the wild and bizarre
# discussion styles sometimes seen in certain Usenet groups and Internet forums.
#
# [9] https://firstlook.org/theintercept/20144/02/24/jtrig-manipulation

# A potentially possible improvement of PKI for personal communications in
# countries like Germany is to let the registration authority that issues
# the identity cards to enter into a publically accessible list the public keys
# of the citizens. See a note of the present author
# http://s13.zetaboards.com/Crypto/topic/7430983/1/.

# Independent of the issue of CAs, RSA has anyway the advantage over symmetric
# encryption schemes in key management in that, for m persons to communicate,
# only m secret keys have to be kept instead of m*(m-1) ones. The public keys
# need be correctly distributed but are of course by nature non-secret and
# hence simpler to be kept.

# For two communication partners who are well acquainted with each other, the
# verification of authentication of public keys obtained via emails could e.g.
# be done by sending test messages and checking their contents over telephone.
# The digits of the public key could, though inconvenient, of course also be
# directly verified over telephone. (See though a remark on risks of voice
# channel above.)

# According to time measurements, use of RSA moduli of the order of even 8000
# bits (current practice 2000) is well acceptable for our targeted users, i.e.
# they could without problems employ more conservative moduli sizes. Note
# that the cpu time of generation, on the average of 100 sec for the case of
# 8000 bits, is only a one-time expense. It may be remarked that for digital
# signatures (which as a rule would be less frequently needed by our targeted
# users but which may need to take care of future enhanced key size requirements
# during a very long validity time of the documents), the signer could employ
# a different larger modulus than the one that is used for normal encryption
# processing (for protection of secrets of comparatively short expiration
# dates). Similarly one could employ an appropriate arbitrarily sized modulus
# for RSA PRBG generation. In Example 5, in distinction to Example 3, 4 and 3S,
# a very low (albeit often employed in practice) value of e=3 is used in order
# to avoid extreme inefficiency and we choose to employ a comparatively larger
# modulus. Note that for PRBG generation, the bit sequence and the modulus are
# commonly employed only one-time and discarded subsequently. (Example 5 may
# eventually have a comparatively much longer processing time than the other
# examples due to the longer time needed for its modulus generation.)

# If desired, multiple encryptions could be done. Thus the output of
# rsaencryptplaintexttoct() could be further processed (coding for this could
# be simply done with Python's pow()) with a second different public key (with
# an appropriate larger modulus, noting that the integers in the list ct may be
# larger then mb bits) of the receiver. Another possibility is to first encrypt
# the given plaintext string with e.g. a symmetric encryption scheme and then
# process the resulting ciphertext string or byte sequence with
# rsaencryptplaintexttoct() or rsaencryptbytearraytoct(). In this context the
# following software of the present author may be of some interest:
# DIGRAMSUB (http://s13.zetaboards.com/Crypto/topic/9011356/1/)
# BASICS (http://s13.zetaboards.com/Crypto/topic/7425974/1/)
# NONLIN (http://s13.zetaboards.com/Crypto/topic/7416010/1/)
# BITPERM (http://s13.zetaboards.com/Crypto/topic/7404266/1/)
# AES/Python (http://s13.zetaboards.com/Crypto/topic/7385224/1/)
# RANDOMPREFIX (http://s13.zetaboards.com/Crypto/topic/7380698/1/)
# HOMOPHONE (http://s13.zetaboards.com/Crypto/topic/7357199/1/)
# PREFIXCODING (http://s13.zetaboards.com/Crypto/topic/7164646/1/)
# PERMPOLYSP (http://s13.zetaboards.com/Crypto/topic/7590068/1/)
# WORDLISTSUB (http://s13.zetaboards.com/Crypto/topic/7219745/1/)
# SHUFFLE2 (http://s13.zetaboards.com/Crypto/topic/6925232/1/)

# Also may be mentioned are two steganographical schemes for embedding bit
# sequences in texts, which hopefully a few users may find useful under certain
# special circumstances that necessitate information hiding techniques:
# EMAILSTEGANO (http://s13.zetaboards.com/Crypto/topic/6939954/1/) and
# WORDLISTTEXTSTEGANOGRAPHY (http://s13.zetaboards.com/Crypto/topic/9024439/1/,
# see also http://s13.zetaboards.com/Crypto/topic/7518381/1/)
# a PRNG: PERMPOLYPRNG (http://s13.zetaboards.com/Crypto/topic/7355166/1/)
# and a utility for combining text files via unbiasing etc.:
# TEXTCOMBINE (http://s13.zetaboards.com/Crypto/topic/7346322/1/)
# an improvement of the classical Playfair cipher for manual encryption:
# http://s13.zetaboards.com/Crypto/topic/7519154/1/
# and a suggestion of a way to derive from an arbitrary given block cipher a new 
# block cipher with doubled block length and doubled key length:
# http://s13.zetaboards.com/Crypto/topic/7504586/1/

# The present author likes to stress once again that for securing the privacy
# of communications of the common people, which are naturally of very low
# volumes, computing time of encryption processing (of the order of seconds at
# most) is in no case of any practical significance. On the other hand, it is
# of absolutely critical importance that in no case bugs (e.g. Heartbleed) or,
# worse, implanted backdoors exist in the software being employed. Consequently
# encryption software that are small in size, clearly written and fairly simple
# to be verified to be correct to well serve their purposes are definitely
# to be preferred.

# For personal communications within a finite group of common people we like to
# remark: (1) This software is self-sufficient in that users could employ but
# does not necessarily need at all an additional software to perform symmetric
# encryption processing (which is commonly the practice currently for efficiency
# reasons). (2) The public keys e's are needed by the communication partners but
# need not be propagated/known to the outside world. What one enjoys from use of
# RSA is that there is no need to take extreme care of the e's and the reduction
# of the total number of keys to be managed in comparison to symmetric
# encryption (if one does as in our Example 3 or 3S without use of any
# additional symmetric encryption). (3) Since the messages of our targeted users
# are generally of small volume, employment of n much larger than 2000 doesn't
# lead to unacceptable encryption time. (4) End-to-end encryption, which is
# often praised as the solution to attain good privacy, could in reality
# nonetheless be insecure, if the RSA key generation is done with proprietary
# software (or with huge open-source software that due to their sizes have not
# been closely examined by independent experts and certified to be ok), see the
# last paragraph below for the feasibility of imdedding a back door in them.

# Under non-democratic regimes, communications with encrypted stuffs could be
# a highly difficult problem facing especially the regime critics and activists.
# Note that remailers, e.g. Tor, though often praised to be helpful for these
# people, are principally insecure under universal surveillance, for the secret
# agencies could e.g. tap on the side of the Internet providers of them and get
# their IP-addresses from their emails. The claimed "sender anonymity" (assuming
# that a remailer works properly) is only true with respect to the site of the
# receiver (i.e. from an email obtained by the receiver it is impossible to
# uniquely identify from which IP-address it was originally sent) but doesn't
# protect at all against sender identification (in the sense of finding persons
# who send out encrypted stuffs at all) by mighty secret agencies that have
# control over the connection line between the sender and his Internet service
# provider or even control over the ISP itself. (In fact a message sent to an
# entrance point of a remailer is defacto calling particular attention to the
# omni-potent agencies that here is a message whose sender evidently has a 
# special need to conceal his identity, while otherwise the message would have
# been just one of all those being transmitted over the Internet and would 
# hence been much more difficult for the agencies to find/search despite their 
# incredibly huge computing and other resources.) Nor can it be avoided that
# IP-addresses that receive emails containing encrypted stuffs be identified by
# such agencies. An eventually feasible method of avoiding such identifications
# is that the sender with appropriate carefulness -- against possible
# observations by secret agents etc., noting also that publically used computers
# may be infected by malware/spyware, have key-loggers etc., that use of USB
# sticks has the diverse well-known risks, that computers of a cluster may be
# accessed by those having administrator rights and that one's current location
# may be tracked via one's mobile phone even when it is powered off (unless it
# is isolated with a tested (via trying connections when phone in bag and on)
# and properly used Faraday bag (on sale inexpensively) or a wrapping consisting
# of a sufficient number of layers of aluminium foils) and that past tracking
# records could be useful to the adversary for inference purposes -- posts the
# encrypted stuffs from an Internet cafe or call shop to a Usenet group like
# alt.anonymous.email, employing thereby the IP-addresses of these locations and
# that the receiver similarly obtains the posts, with the posts of the partners
# being identified through certain agreed-upon conventions of the content of the
# subject lines of the posts. The subject lines could e.g. be the result of
# encryption of something agreed upon by the partners (preferably non-constant,
# containing e.g. message serial number etc.) with an arbitrary symmetric
# encryption algorithm so as to avoid collisions with posts of other persons to
# the same Usenet group. Since only distinguishing subject lines of emails to
# the Usenet group are required, this symmetric encryption algorithm could be
# even trivially weak. The receiver doesn't decrypt the subject lines of the
# posts but, prior to checking posts of the sender, performs the same encryption
# as the sender in order to be able to find the relevant posts. Even actual
# collisions wouldn't be disastrous anyway, since that would only lead to some
# wasted efforts in attempting to decrypt messages of foreign persons, obtaining
# rubbish thereby. Certainly it is always preferable to encrypt the proper
# secret messages with good encryption schemes that also provide authentication
# (integrity check).

# In extreme situations, where the partners could communicate with each other
# only via plain natural language texts, the two steganographical schemes listed
# further above of the present author may be employed, though they are
# unfortunately of rather limited efficiency, i..e. practically suitable only
# for transmission of fairly short stego bit sequences.

# While in certain Internet discussions on Tor etc. some strong adherents may be
# sincere though naive, the participation of JTRIG people in them apparently
# couldn't be excluded [9, 10].
#
# [10] http://www.counterpunch.org/2014/07/18/the-nsa-wants-you-to-trust-tor-should-you/

# We note for completeness that, while strong encryption protects secrecy of
# messages, metadata of communications, including time, volume and frequencies,
# could eventually also be meaningful to the adversaries.

# A well-known essential risk of employing RSA encryption comes from the future
# quantum computers, which could render the factorization of its moduli easy and
# hence the scheme practically useless. However, researches in quantum computing
# seems, like the other grand projects in physics, e.g. nuclear fusion, yet
# unlikely to be a reality in the next couple of decades, cf. [11]. It may be
# interesting also to compare with crypto researches in fully homomorphic
# encryption which, despite its initial furore, is apparently yet quite far from
# reaching the desired goal. See also citations and some tiny comments of the
# present author in http://s13.zetaboards.com/Crypto/topic/7457176/1/. (See
# Addendum 1 there. The complexity of quantum tomography, which would be
# required for design and, in particular, maintenance of non-trivial quantum
# circuits presumably could be of such a mangitude in practice that it defacto
# prohibits the construction and usage of sufficiently large quantum computers.)
#
# [11] http://www.theplatform.net/2015/07/22/google-sees-long-expensive-road-ahead-for-quantum-computing/

# We repeat that for communications of our targeted users (the common people)
# that require genuinely secure protection, it could be generally assumed that
# (a) the messages are as a rule of low volume, (b) the computing power of a PC
# is available, (c) processing times of the order of seconds are well
# acceptable, and (d) it is very essential that users could easily have at least
# some fairly superfical comprehension of what is going on and be able to simply
# check and verify with well-known acknowledged textbooks that the coding is
# indeed correct. In this situation it seems evident that a choice between RSA
# and ECC [12] would favour the former being employed and that, as indicated by
# our time measurements, the encryption processing with RSA may generally be
# self-sufficient in practice (i.e. user's secret messages are directly
# encrypted with RSA as done in Example 3 and 3S and not encrypted with a
# symmetric encryption scheme whose key is transported via RSA).
#
# [12] D. Hankerson et al., Guide to Elliptic Curve Cryptography, Springer,
#      2004.

# It cannot be over-emphasized that the public keys of the communication
# partners being used must be authentic, i.e. stemming from the right persons
# and obtained without being manipulated, and that one's secret key must be
# absolutely securely protected against all sorts of potentially possible
# risks, e.g. insider attacks, software/hardware trojans and social enginnering
# etc. The recent highly sophisticated hacking of Kaspersky's network [13] was
# suspected to involve stealth of private keys from FoxConn, though the exact
# way of obtaining the keys, which could potentially be a different one (cf. the
# last paragraph below), would certainly remain unknown. Note anyway however the
# potential far-reaching extreme consequences of loss of private keys.
# Considerations should also be given to issues of key revocation and general
# limitation of the validity periods of the keys.
#
# [13] http://www.theregister.co.uk/2015/06/15/duqu2_stolen_foxconn_cert/

# Evidently, encryption would serve no purpose at all if the adversary could
# manage to install a software/hardware trojan on one's computer that leaks
# processing informations. Thus it may be necessary to employ an additional
# computer that is appropriately isolated from the Internet to do encryption
# processing, with well controlled and checked data transfer between the two
# ("diodes" for unidirectional data transfer or optically via scanning (incl.
# QR codes), or other suitable means), noting that USB devices etc. may be
# susceptible to attacks. See however [8, 14, 15, 16, 17, 18] for sources of
# risks. It may be noted that, in order to protect against emission risks,
# besides taking appropriate shielding measures it may under circumstances be
# feasible also to generate noises in the emission range so as to avoid
# exploitable signal informations being obtained by the adversary.
#
# [14] http://www.wired.com/2015/03/stealing-data-computers-using-heat/
# [15] http://www.wired.com/2015/07/researchers-hack-air-gapped-computer-simple-cell-phone/
# [16] http://www.wired.com/2015/08/researchers-create-first-firmware-worm-attacks-macs/
# [17] S. Sethumadhavan et al. Trustworthy Hardware from Untrusted Components,
#      CACM vol.58 (2015), p.60-71.
# [18] http://http://s13.zetaboards.com/Crypto/topic/7494408/1/

# While strong encryption ensures secrecy of messages, the quality of the
# Internet communication connection between the partners can obviously be
# subjected to diverse attacks by mighty adversaries, including delays,
# modifications and suppressions. Unfortunately there seems to be barely any
# practically feasible mitigations in this respect for the purposes of our
# tageted users, the common people. We mention nonetheless for completeness that
# one alternative which could eventually work in certain situations, assuming
# availability of corresponding financial and technical resources, is to have
# a private network, which could be cabled, via radio or optical. (It is of some
# historical interest that about a decade ago there existed in the Czech
# Republic "Ronja" which operated with red and infrared light. The general and
# essential leakage problem of free-space optical communication presumably could
# be sufficiently well dealt with in certain favourable circumstances by
# employing laser as medium.)

# Very long ago, way before Snowden's revelations, the present author suggested
# in a Usenet group that one "conceivable" way of defeating extensive
# surveillance by the agencies could be that most people of the world regularly
# have in their emails certain lines attached that are "apparently" hexadecimal
# outputs of encryptions. That is, they just put in some random sequences even
# though they don't have secret messages to exchange with one another. For,
# that way the computers of the agencies would be heavily overloaded in
# attempting to decrypt these dummies, which by definition can never succeed.
# However, the sad natural fact is clearly that most people of the world
# wouldn't like to take these efforts, since these would mean additional work
# for them that don't have any financial or other compensations that are deemed
# really worthy for them.

# There are two fundamental troubling issues facing developers of crypto
# software: (1) The possible application fields of any crypto scheme are in
# general too manifold to be ever equally well covered by any individual
# designs, if at all. (2) An encryption software, if found useful in practice,
# can be employed by good as well as bad people. To (1) one easily sees that
# in paraticular cyber physical systems and IOT (Internet of Things) are so huge
# in dimensions and rapid in expansions that any hope of a satisfactory solution
# of their security problems including, among others, trust managment and
# prevention of software/hardware backdoors, appear to be as illusory as in the
# analogous cases of world climate, famine and health-epidemic problems etc.
# However, this certainly doesn't mean that we shouldn't attempt to do any
# feasible mitigations nonetheless. In that the design of the present software
# is mainly targeted to the highly limited application field of the
# communications of the common people, we hope that it has well satisfied its
# goal of safeguarding their privacy with acceptable work of use and efficiency.
# To (2) one should note the analogy with kitchen knives whose manufacture
# obviously shouldn't be stopped simply because these apparatus could be used as
# weapon to kill people as well. If one takes in this connection also the fact
# into consideration that belligerent countries of the world are even actively
# preparing for cyberwars, the urgent necessity and rights of the innocent
# civilians to defend their own bare personal privacy interests become entirely
# self-evident in our view.

# There has been a question on PCBC employed in the scheme in our Ex.3 in
# crypto.stackexchange.com/questions/38136/. See my comment there in which a
# link is given to a long discussion with MaartenBodewes, to whom I responded at
# the end with "Assuming that RSA is as secure as BlockCipher XYZ, this will
# give the same security as PCBC used with XYZ, when the input sequences to be
# dealt with are normally input from a keyboard or else are binaries resulting
# from other encryption schemes (excepting a practically negligible probability
# value, as I mentioned earlier)."

# That backdoors could easily be imbeded into proprietary RSA software was
# treated in a Usenet group long ago. The present author suggested the use of
# a limited number of secretly chosen ratios p/q to be employed in the key
# generation process which could be exhaustively tried by the analyst who knows
# that backdoor. A much better and more flexible idea is due to maartin, who
# gave a sketch of his idea, albeit unfortunately in such short wordings that it
# was apparently not closely examined by the readers at that time and henceforth
# entirely ignored. The present author recently remembered maartin's idea and
# tried it out in an implementation as follows: Suppose one generates RSA keys
# with modulus n = p*q > 2**mb for mb=2000. Generate a pseudo-random
# comparatively small, say 256-bit (full), value head to be the leading part of
# n. Use head as a parameter to uniquely generate a prime p of mb//2 bits.
# Different ways of designing such a unique mapping are obviously conceivable.
# In our implementation head is used to seed a PRNG to generate a pseudo-random
# mb//2-bit value ptemp and one finds the next prime p after ptemp with
# Miller-Rabin. Let ltail = mb + 2 - 256. Generate a pseudo-random value tail of
# ltail bits. Concatenate head and tail to be ntemp. With qtemp = ntemp//p find
# the next prime q after qtemp with Miller-Rabin. Compute n = p*q. If n < 2**mb,
# repeat the above procedure. This way, the n generated will have its leading
# 256 bits identical to head. Thus a person knowing this backdoor can simply get
# the value of head from n and with it recover p in the way mentioned above and
# obtain then q and do everything of the original RSA key generation. It should
# be crystal clear therefore that for "genuine" security one should generate
# oneself one's own RSA keys with an open-source software like the present one
# which, being fairly small, can be easily verified to be correct and free of
# backdoors. At the beginning of 2011, way before the theme of universal
# surveillance attains its popularity of today, the present author sent emails
# mentioning maartin's idea to a number of institutions -- domestic as well as
# international ones -- that are clearly responsible/relevant in the issues
# conerned, warning them of the potential risks of backdoors in proprietary RSA
# software and simultaneously of the questionable trustworthiness of CA's in
# general, without however ever obtaining a tiniest echo from them. (As a side
# note: Not having to do with RSA but with Diffie-Hellman, see
# http://weakdh.org/imperfect-forward-secrecy.pdf,
# http://eprint.iacr.org/2016/644.pdf, http://eprint.iacr.org/2016/961,
# https://arxiv.org/abs/1608.07032, http://eprint.iacr.org/2016/999 and
# http://blog.intothesymmetry.com/2016/10/the-rfc-5114-saga.html.)
