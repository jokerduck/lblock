from CNF import CNF
import sys

Perm=[7, 4, 1, 6, 3, 0, 5, 2]
def GenNibblePerms(HalfBlockSize, nibble_perms=[7,4,1,6,3,0,5,2]):
    perms = [0 for i in range(HalfBlockSize)]
    assert len(nibble_perms) == HalfBlockSize // 4
    for i in range(HalfBlockSize):
        nibble_index = i // 4
        nibble_possition = i % 4
        perms[i] = 4 * nibble_perms[nibble_index] + nibble_possition

    return perms

def PassLinear( X ):
    Y = X[:]
    for i in range(64):
        X[ Perm[i] ] = Y[i]

class SAND( CNF ):
    def __init__( self ):
        CNF.__init__( self )
        # SboxConstr

    def genModel( self,Round,ini,outj):
        self.reset()

        X = [ [ self.gen_var() for i in range( 32 ) ] for j in range(Round + 1)]
        Y = [ [ self.gen_var() for i in range( 32 ) ] for j in range(Round + 1)]
        in_G=[[ self.gen_var() for i in range( 32 ) ] for j in range(Round)]
        in_G0=[[ self.gen_var() for i in range( 32 ) ] for j in range(Round)]
        in_G1=[[ self.gen_var() for i in range( 32 ) ] for j in range(Round)]
        and_G0=[[ self.gen_var() for i in range( 16 ) ] for j in range(Round)]
        and_G1=[[ self.gen_var() for i in range( 16 ) ] for j in range(Round)]
        xor_G0=[[ self.gen_var() for i in range( 32 ) ] for j in range(Round)]
        xor_G1=[[ self.gen_var() for i in range( 32 ) ] for j in range(Round)]
        xor_G=[[ self.gen_var() for i in range( 32 ) ] for j in range(Round)]
        perm_G=[[ self.gen_var() for i in range( 32 ) ] for j in range(Round)]

        self.setini(X[0],Y[0],ini)
        self.setoutj(X[Round],Y[Round],outj)
        
        for r in range(Round): 
            self.gen_varCOPY(X[r],Y[r+1],in_G[r])
            self.gen_varCOPY(in_G[r],in_G0[r],in_G1[r])
            for i in range(8):
                self.gen_and(in_G0[r][i*4+3],in_G0[r][i*4+2],and_G0[r][i])
                self.gen_and(in_G1[r][i*4+3],in_G1[r][i*4+1],and_G1[r][i])
                self.gen_and(xor_G0[r][i*4],in_G0[r][i*4+1],and_G0[r][i+8])
                self.gen_and(xor_G1[r][i*4+2],in_G1[r][i*4],and_G1[r][i+8])
                self.gen_xor(and_G0[r][i],in_G0[r][i*4],xor_G0[r][i*4])
                self.gen_xor(and_G0[r][i+8],in_G0[r][i*4+3],xor_G0[r][i*4+3])
                self.gen_xor(and_G1[r][i],in_G1[r][i*4+2],xor_G1[r][i*4+2])
                self.gen_xor(and_G1[r][i+8],in_G1[r][i*4+1],xor_G1[r][i*4+1])
                self.gen_assign(xor_G0[r][i*4+2],in_G0[r][i*4+2])
                self.gen_assign(xor_G0[r][i*4+1],in_G0[r][i*4+1])
                self.gen_assign(xor_G1[r][i*4+3],in_G0[r][i*4+3])
                self.gen_assign(xor_G1[r][i*4],in_G0[r][i*4])
                
            rot_G1=xor_G1[r][4:]+xor_G1[r][:4]
            self.gen_varXOR(xor_G0[r],rot_G1,xor_G[r])
            for i in range(32):
                nibble_index = i // 4
                nibble_possition = i % 4
                aftp=4 * Perm[nibble_index] + nibble_possition
                self.gen_assign(xor_G[r][i],perm_G[r][aftp])

            self.gen_varXOR(perm_G[r],Y[r],X[r+1])

        # exclude the trivial result
        #self.gen_constr_exclude_vector( X[0], [ ['0'] * 64 ] )
        #self.seq_sum( P, obj )

        return X, Y

if __name__ == '__main__':
    Round = 13
    sand = SAND ()
    cnf = 'sand.cnf'  
    X, Y = sand.genModel( Round,31,14 )
    print(X)
    sand.printCNF( cnf )
    res_dict={}
    res = sand.runCNF ( cnf, res_dict )
    print(res)

