
%% SHA-256 Hashing Function
%{ 
    Methodology
1. Preprocessing Stage
a) Padding a message
b. Parsing the padded message into m-bit blocks
c) Setting initialization values

2. Hash Coputation Stage
a) Message Schedule
b) Intermediate hash value computation using the message schedule,
   functions, constants and word operations
c) Append hash values to represent the message digest.

%}
function [MDigest,TimeStamp] = HashFunction(input)

[MBlock,InitialHashVec] = PreHashProcess(input);
W = [];
HASHVEC = [];

%% Message Schedule Wt
for i = 1:16
   W(i,:) = MBlock(i,:);  
end

[Length,~] = size(MBlock);

%Extending the first 16 words into a total the 64 words
   for j = 17:64
       s0_ = xor( (circshift(W(j-15,:),7)) , (circshift(W(j-15,:),18)) );
       s0 = xor( s0_ , LogicalRightShift( W(j-15,:),3 ));
       
       s1_ = xor( (circshift(W(j-2,:),17)) , (circshift(W(j-2,:),19)) );
       s1 = xor( s1_ , LogicalRightShift( W(j-2,:),10 ));
       
       %Convert to decimal is can apply addition modulo
       Wdec0 = bi2de( W(j-16,:) , 'left-msb' );
       Wdec1 = bi2de( W(j-7,:) , 'left-msb' );
       sdec0 = bi2de( s0 , 'left-msb' );
       sdec1 = bi2de( s1 , 'left-msb' );
       
       sum = Wdec0 + sdec0 + Wdec1 + sdec1;
       AMsum = mod(sum, 2^32);
       
       W_ = de2bi( AMsum , 'left-msb' , 32 );
       W_ = logical(W_);
       W = [ W ; W_];
   end 

    W = logical(W);

%% Initialize working register a - h
InitialHashVec_ = hexToBinaryVector(InitialHashVec);
a = InitialHashVec_(1,:);
b = InitialHashVec_(2,:);
c = InitialHashVec_(3,:);
d = InitialHashVec_(4,:);
e = InitialHashVec_(5,:);
f = InitialHashVec_(6,:);
g = InitialHashVec_(7,:);
h = InitialHashVec_(8,:);

%% Initialize the array constants
   
   Hconst = [ '428a2f98' ; '71374491' ; 'b5c0fbcf'; 'e9b5dba5'; '3956c25b';
              '59f111f1' ; '923f82a4' ; 'ab1c5ed5'; 'd807aa98'; '12835b01';
              '243185be' ; '550c7dc3' ; '72be5d74'; '80deb1fe'; '9bdc06a7';
              'c19bf174' ; 'e49b69c1' ; 'efbe4786'; '0fc19dc6'; '240ca1cc';
              '2de92c6f' ; '4a7484aa' ; '5cb0a9dc'; '76f988da'; '983e5152';
              'a831c66d' ; 'b00327c8' ; 'bf597fc7'; 'c6e00bf3'; 'd5a79147';
              '06ca6351' ; '14292967' ; '27b70a85'; '2e1b2138'; '4d2c6dfc';
              '53380d13' ; '650a7354' ; '766a0abb'; '81c2c92e'; '92722c85';
              'a2bfe8a1' ; 'a81a664b' ; 'c24b8b70'; 'c76c51a3'; 'd192e819';
              'd6990624' ; 'f40e3585' ; '106aa070'; '19a4c116'; '1e376c08';
              '2748774c' ; '34b0bcb5' ; '391c0cb3'; '4ed8aa4a'; '5b9cca4f';
              '682e6ff3' ; '748f82ee' ; '78a5636f'; '84c87814'; '8cc70208';
              '90befffa' ; 'a4506ceb' ; 'bef9a3f7'; 'c67178f2'];
          
    Hconst_ = hexToBinaryVector(Hconst,32);

%% Compression Function Main Loop
for k = 1:64
   
    S1_ = xor( circshift(e,6) , circshift(e,11) );
    S1 = xor( S1_ , circshift(e,25) );
    ch = xor( (e & f) , (~e & g) );
    
    %% Convert to decimal to do Addition Modulo of 2^32
    hdec = bi2de( h , 'left-msb' );
    Sdec1 = bi2de( S1 , 'left-msb' );
    chdec = bi2de( ch , 'left-msb' );
    Hconstdec = bi2de( Hconst_(k,:) , 'left-msb' );
    Wdec = bi2de( W(k,:) , 'left-msb' );
    
    sum1 = hdec + Sdec1 + chdec + Hconstdec + Wdec;
    sum1 = mod(sum1, 2^32);
    
    %%
    S0_ = xor( circshift(a,2) , circshift(a,13) );
    S0 = xor( S0_ , circshift(a,22) );
    maj_ = xor( (a & b) , (a & c) );
    maj = xor( maj_ , (b & c));
    
    %% Convert to decimal to do Addition Modulo of 2^32
    Sdec0 = bi2de( S0 , 'left-msb' );
    majdec = bi2de( maj , 'left-msb' );
    
    sum2 = Sdec0 + majdec;
    sum2 = mod(sum2 , 2^32);
    
    %% Shifting of the variables
    
    h = g;
    g = f;
    f = e;
    
     %% Convert d into a dec and take the Addition Modulo
     ddec = bi2de( d , 'left-msb' );
     sum3 = ddec + sum1; 
     sum3 = mod(sum3, 2^32);
     e = de2bi(sum3,32,'left-msb');
     e = logical(e);
     
    %%
    d = c;
    c = b;
    b = a;
    
    %% Convert d into a dec and take the Addition Modulo
    sum4 = sum1 + sum2;
    sum4 = mod(sum4, 2^32);
    a = de2bi(sum4 , 32 , 'left-msb');
    a = logical(a);
    
%% Hash value for each round
HASH_ = [a b c d e f g h];
HASH = binaryVectorToHex(HASH_);
HASHVEC = [HASHVEC; HASH];

end
    %% Message Digest Computation, converting from binary to decimal
 ad = bi2de(a, 'left-msb');
 bd = bi2de(b, 'left-msb');
 cd = bi2de(c, 'left-msb');
 dd = bi2de(d, 'left-msb');
 ed = bi2de(e, 'left-msb');
 fd = bi2de(f, 'left-msb');
 gd = bi2de(g, 'left-msb');
 hd = bi2de(h, 'left-msb');
 
 ha_ = bi2de(InitialHashVec_(1,:),'left-msb');
 hb_ = bi2de(InitialHashVec_(2,:),'left-msb');
 hc_ = bi2de(InitialHashVec_(3,:),'left-msb');
 hd_ = bi2de(InitialHashVec_(4,:),'left-msb');
 he_ = bi2de(InitialHashVec_(5,:),'left-msb');
 hf_ = bi2de(InitialHashVec_(6,:),'left-msb');
 hg_ = bi2de(InitialHashVec_(7,:),'left-msb');
 hh_ = bi2de(InitialHashVec_(8,:),'left-msb');
 
 %% Addition Modulo 2^32 and converting the decimal value to hex
 
 h0_ = mod(ha_ + ad , 2^32);
 h0_ = de2bi(h0_ , 32 , 'left-msb');
 h0 = binaryVectorToHex(h0_);
 
 h1_ = mod(hb_ + bd , 2^32);
 h1_ = de2bi(h1_ , 32 , 'left-msb');
 h1 = binaryVectorToHex(h1_);
 
 h2_ = mod(hc_ + cd , 2^32);
 h2_ = de2bi(h2_,32,'left-msb');
 h2 = binaryVectorToHex(h2_);
 
 h3_ = mod(hd_ + dd , 2^32);
 h3_ = de2bi(h3_,32,'left-msb');
 h3 = binaryVectorToHex(h3_);

 h4_ = mod(he_ + ed , 2^32);
 h4_ = de2bi(h4_,32,'left-msb');
 h4 = binaryVectorToHex(h4_);
 
 h5_ = mod(hf_ + fd , 2^32);
 h5_ = de2bi(h5_,32,'left-msb');
 h5 = binaryVectorToHex(h5_);
 
 h6_ = mod(hg_ + gd , 2^32);
 h6_ = de2bi(h6_,32,'left-msb');
 h6 = binaryVectorToHex(h6_);
 
 h7_ = mod(hh_ + hd , 2^32);
 h7_ = de2bi(h7_,32,'left-msb');
 h7 = binaryVectorToHex(h7_);
 
 %% Message Digest
 MDigest = [h0 h1 h2 h3 h4 h5 h6 h7];
 
 %% Time Stamp
TimeStamp = datetime('now');

end
