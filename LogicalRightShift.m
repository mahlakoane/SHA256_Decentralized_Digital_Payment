
function vector = LogicalRightShift(W,j)

    W = circshift(W,j);
    %Shifts bits to the right by j spaces, when the bit rolls off the array
    %its not moved to the left end. The left end gets a zero.
    W(1:j) = 0;
    vector = W;

end