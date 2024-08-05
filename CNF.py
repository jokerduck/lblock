import os
import result

class CNF: 
    def __init__( self ):
        self._V = 0
        self._clause = []

    def reset( self ):
        self._V = 0
        self._clause = []

    def addClause( self, c ):
        # add Construct
        self._clause.append( c )

    # X[0] + ... + X[] <= k
    def seq_sum( self, X, k ):
        if k > 0:
            n = len( X )
            S = [ [ self.gen_var() for i in range( k ) ] for j in range( n - 1 ) ]
            s = '-%d %d 0' % ( X[0], S[0][0] )
            self.addClause( s )

            for j in range(1, k):
                s = '-%d 0' % ( S[0][j] )
                self.addClause( s )

            for i in range( 1, n - 1 ):
                s = '-%d %d 0' % ( X[i], S[i][0] )
                self.addClause( s )
                s = '-%d %d 0' % ( S[i - 1][0], S[i][0] )
                self.addClause( s )

                for j in range(1, k):
                    s = '-%d -%d %d 0' % ( X[i], S[i - 1][j - 1], S[i][j] )
                    self.addClause( s )
                    s = '-%d %d 0' % ( S[i - 1][j], S[i][j] )
                    self.addClause( s )

                s = '-%d -%d 0' % ( X[i], S[i- 1][k - 1] )
                self.addClause( s )

            s = '-%d -%d 0' % ( X[n - 1], S[n - 2][k - 1] )
            self.addClause( s )

        else:
            for x in X:
                s =  '-%d 0' % x
                self.addClause( s )

    # addVar
    def gen_var( self ):
        self._V += 1
        return self._V

    def gen_assign(self,X,Y):
        s1=''
        s2=''
        s1+='-%d '%(X)
        s1+='%d 0'%(Y)
        self.addClause( s1 )
        s2+='%d '%(X)
        s2+='-%d 0'%(Y)
        self.addClause( s2 )

        
    def gen_xor(self,X,Y,Z):
        #X^Y=Z
        s1=''
        s2=''
        s3=''
        s4=''
        s1+='-%d '%(X)
        s1+='-%d 0'%(Y)
        self.addClause( s1 )
        s2+='%d '%(X)
        s2+='%d '%(Y)
        s2+='-%d 0'%(Z)
        self.addClause( s2 )
        s3+='-%d '%(X)
        s3+='%d '%(Y)
        s3+='%d 0'%(Z)
        self.addClause( s3 )
        s4+='%d '%(X)
        s4+='-%d '%(Y)
        s4+='%d 0'%(Z)
        self.addClause( s4 )
        
    def gen_varXOR(self,X,Y,Z):
        #X^Y=Z
        L=len(X)
        for i in range(L):
            s1=''
            s2=''
            s3=''
            s4=''
            s1+='-%d '%(X[i])
            s1+='-%d 0'%(Y[i])
            self.addClause( s1 )
            s2+='%d '%(X[i])
            s2+='%d '%(Y[i])
            s2+='-%d 0'%(Z[i])
            self.addClause( s2 )
            s3+='-%d '%(X[i])
            s3+='%d '%(Y[i])
            s3+='%d 0'%(Z[i])
            self.addClause( s3 )
            s4+='%d '%(X[i])
            s4+='-%d '%(Y[i])
            s4+='%d 0'%(Z[i])
            self.addClause( s4 )
    def gen_varCOPY(self, X, Y, Z):
        #X->(Y,Z)
        L=len(X)
        for i in range(L):
            s1=''
            s2=''
            s3=''
            s4=''
            s1+='-%d '%(Y[i])
            s1+='-%d 0'%(Z[i])
            self.addClause( s1 )
            s2+='%d '%(X[i])
            s2+='%d '%(Y[i])
            s2+='-%d 0'%(Z[i])
            self.addClause( s2 )
            s3+='%d '%(X[i])
            s3+='-%d '%(Y[i])
            s3+='%d 0'%(Z[i])
            self.addClause( s3 )
            s4+='-%d '%(X[i])
            s4+='%d '%(Y[i])
            s4+='%d 0'%(Z[i])
            self.addClause( s4 )
    def gen_and(self,X,Y,Z):
        #X&Y=Z
        s1=''
        s2=''
        s3=''
        s1+='-%d '%(Y)
        s1+='%d 0'%(Z)
        self.addClause( s1 )
        s2+='%d '%(X)
        s2+='%d '%(Y)
        s2+='-%d 0'%(Z)
        self.addClause( s2 )
        s3+='-%d '%(X)
        s3+='%d 0'%(Z)
        self.addClause( s3 )
        

    def setini( self,X,Y,ini):
        if ini<32:
            s1='-%d 0'%(X[ini])
            self.addClause( s1 )
            s2='%d 0'%(Y[ini])
            self.addClause( s2 )
            for i in range(32):
                if i==ini:
                    continue
                s1='%d 0'%(X[i])
                self.addClause( s1 )
                s2='%d 0'%(Y[i])
                self.addClause( s2 )
        if ini>=32:
            s1='%d 0'%(X[ini%32])
            self.addClause( s1 )
            s2='-%d 0'%(Y[ini%32])
            self.addClause( s2 )
            for i in range(32):
                if i==ini%32:
                    continue
                s1='%d 0'%(X[i])
                self.addClause( s1 )
                s2='%d 0'%(Y[i])
                self.addClause( s2 )
    def setoutj( self,X,Y,outj):
        if outj<32:
            s1='%d 0'%(X[outj])
            self.addClause( s1 )
            s2='-%d 0'%(Y[outj])
            self.addClause( s2 )
            for i in range(32):
                if i==outj:
                    continue
                s1='-%d 0'%(X[i])
                self.addClause( s1 )
                s2='-%d 0'%(Y[i])
                self.addClause( s2 )
        if outj>=32:
            s1='-%d 0'%(X[outj%32])
            self.addClause( s1 )
            s2='%d 0'%(Y[outj%32])
            self.addClause( s2 )
            for i in range(32):
                if i==outj%32:
                    continue
                s1='-%d 0'%(X[i])
                self.addClause( s1 )
                s2='-%d 0'%(Y[i])
                self.addClause( s2 )

    def gen_constr_exclude_vector( self, X, V ):
        '''
        X = [x0,x1,x2,x3]
        V = [[[0,0,0,1],[1,1,1,1]]
        '''
        L = len( X )
        for v in V:
            s = ''
            for i in range(L):
                if v[i] == '1' or v[i] == 1:
                    s += '-%d ' % ( X[i] ) 
                elif v[i] == '0' or v[i] == 0:
                    s += '%d ' % ( X[i] ) 
                else:
                    pass
            s += '0' 
            self.addClause( s )

    def exclude_sol( self, X, V ):
        L = len( X )
        assert len(V) == L
        #print( X )
        #print( V )

        s = ''
        for i in range(L):
            if V[i] == 1:
                s += '-%d ' % ( X[i] ) 
            elif V[i] == 0:
                s += '%d ' % ( X[i] ) 
            else:
                pass

        s += '0' 

        #print ( s )

        self.addClause( s )

    def printCNF( self, filename ):
        #print( 'Self.V', self._V )
        with open( filename, 'w' ) as f:
            f.write( 'p cnf %d %d \n' % ( self._V, len(self._clause ) ) ) 
            for clause in self._clause:
                f.write( '%s \n' % clause ) 

    def runCNF( self, cnf, res_dict ):
        os.system( 'kissat -q %s > %s.res' % ( cnf, cnf ) )

        flag, resdict = result.parse( '%s.res' % cnf )

        res_dict.update( resdict ) 

        return flag


if __name__ == '__main__':
    # V is all the illegal solution
    V = [ [0, 0, 1], [0, 1, 0], [1, 0, 0], [1, 1, 1], [0,0,0], [0,1,1], [1,0,1], [1,1,0] ]
    CNF = CNF()
    X = [ CNF.gen_var() for i in range(3) ]
    CNF.gen_constr_exclude_vector( X, V ) 
    CNF.printCNF( 'test.cnf' ) 

    res_dict = {}
    flag = CNF.runCNF( 'test.cnf', res_dict)

    print(flag)



