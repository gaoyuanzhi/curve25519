p = 2**255 - 19
d = 37095705934669439343138083508754565189542113879843219016388785533085940283555

def pointAdd( P, Q ):
	A = ( P[1] - P[0] ) * ( Q[1] - Q[0] ) % p
	B = ( P[1] + P[0] ) * ( Q[1] + Q[0] ) % p
	C = 2 * P[3] * Q[3] * d % p
	D = 2 * P[2] * Q[2] % p
	E = B-A
	F = D-C
	G = D+C
	H = B+A
	X3 = E*F
	Y3 = G*H
	Z3 = F*G
	T3 = E*H
	return ( X3, Y3, Z3, T3 )

def pointMul(s, P):
    Q = (0, 1, 1, 0)  # Neutral element
    while s > 0:
        if s & 1:
            Q = pointAdd(Q, P)
        P = pointAdd(P, P)
        s >>= 1
    return Q

def pointEqual( P, Q ):
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True