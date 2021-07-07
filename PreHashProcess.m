
%% SHA-256 Pre-Hashing Processing Function
function [MBlock,InitialHashVec] = PreHashProcess(input)

Mb = [];
Mhex = [];
MhexVec = [];

%% 8-bit ASCII Equivalent for each character
input = dec2bin(input,8);
[a,~] = size(input);

for i = 1:a
    Mb = [Mb input(i,:)];
end

%% Padding the message Mb
[~,MLength] = size(Mb);
l = MLength;
step = 0;

while mod(MLength,512)~=448
    if step == 0
        Mb = [Mb '1']; %Pad a single 1
    else
        Mb = [Mb '0']; %Pads multiple 0 bits 
    end
    
    [~,MLength] = size(Mb);
    step = step + 1;
end

    biLength = dec2bin(l,64); %Converts the length of the array into binary
    
    %Final Padding
    Mb = [Mb biLength];
    
    %% Convert Array into a vector
    Mb = Mb(1,:) - '0';
    [~,padLength] = size(Mb);
    
    if padLength ~= 512
       disp('Error in Pre-Hashing Process');
       return
    end
    
    Mhex = binaryVectorToHex(Mb);

%% Parsing the message M
    [~,hlength] = size(Mhex);
    
    n = 1;
    for v = 8 : 8 : hlength
        MhexVec = [MhexVec ; Mhex(n:v)];
        n = v + 1;
    end
    MBlock = hexToBinaryVector(MhexVec,32);
   
%% Setting the Initial Hash Values
h0 = '6a09e667';
h1 = 'bb67ae85';
h2 = '3c6ef372';
h3 = 'a54ff53a';
h4 = '510e527f';
h5 = '9b05688c';
h6 = '1f83d9ab';
h7 = '5be0cd19';

InitialHashVec = [h0;h1;h2;h3;h4;h5;h6;h7];

end
   
    
    
    