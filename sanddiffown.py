from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import GenPerm as GenPerm
from ciphers import ssb_ddt

from parser.stpcommands import getStringLeftRotate as rotl

class Cipher(AbstractCipher):


    name="lblock"
    rot_alpha=8
    PERM=[]

    def getFormatString(self):

        return ['x','y',
                "outS",
                "roty",
                "outP",
                ,"sumw"]

    def createSTP(self,stp_filename,parameters):

        wordsize=parameters["worldsize"]
        rounds=parameters["rounds"]
        weight=parameters["weight"]

        if wordsize==32:
            p=[1,3,0,2,5,7,4,6]
        elif wordsize==64:
            p = [14, 15, 8, 9, 2, 3, 12, 13, 6, 7, 0, 1, 10, 11, 4, 5]
        else:
            raise Exception("Wrong wordsize!")
        self.PERM = GenPerm.GenNibblePerms(wordsize, p)

        with open(stp_file,'w') as stp_file:
            header=("% Input File for STP: lblock\n"
                      "% w = {} alpha = {} beta = {}\n"
                      "% rounds = {}\n\n".format(
                        wordsize,
                        self.rot_alpha, self.rot_beta,
                        rounds))
            stp_file.write(header)

            x=["x{}" .format(i) for i in range(rounds+1)]
            y=["y{}" .format(i) for i in range(rounds+1)]
            rot_y=["roty{}".format(i) for i in range(rounds)]
            out_S=["outS{}" .format(i) for i in range(rounds)]
            perm_G=["permG{}" .format(i) for i in range(rounds)]

            #总活跃S盒数量
            w=["sumw{}".format(i) for i in range(rounds)]
            #每一轮的活跃s盒数量
            act_flag=["actflag{}".format for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, rot_y, wordsize)
            stpcommands.setupVariables(stp_file, out_S, wordsize)
            stpcommands.setupVariables(stp_file, perm_G, wordsize)
            stpcommands.setupVariables(stp_file, w, 16)
            stpcommands.setupVariables(stp_file, act_flag, wordsize // 4)

            stpcommands.setupWeightComputationSum(stp_file, weight, w, 16)


            self.SBOX_ACT_ASSERT(stp_file)
            for i in range(rounds):
                self.setupRound(stp_file,
                                     x[i], y[i],
                                     x[i+1], y[i+1],
                                     rot_y[i],
                                     out_S[i], 
                                     perm_G[i],
                                     act_flag[i], w[i], wordsize)
                
            stpcommands.assertNonZero(stp_file, [x[0], y[0]], wordsize)

            stpcommands.setupQuery(stp_file)
        return

    
    def setupRound(self,
                        stp_file,
                        x_in, y_in,
                        x_out, y_out,
                        rot_y,
                        out_S, 
                        perm_G,
                        act_flag, w, wordsize):
        """
        Model for differential behaviour of one round
        """
        command = ""

        # 1. y_out = x_in
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        # 2. pass SSb: x -> out_G0, out_G1
        for i in range(wordsize // 4):
            s_in_4_bit = "{0}[{1}:{1}]@{0}[{2}:{2}]@" \
                         "{0}[{3}:{3}]@{0}[{4}:{4}]".format(
                            x_in,
                            wordsize - 1 - 4 * i - 0,
                            wordsize - 1 - 4 * i - 1,
                            wordsize - 1 - 4 * i - 2,
                            wordsize - 1 - 4 * i - 3,
                            )
            s_out_4_bit_S = "{0}[{1}:{1}]@{0}[{2}:{2}]@" \
                             "{0}[{3}:{3}]@{0}[{4}:{4}]".format(
                            out_S,
                            wordsize - 1 - 4 * i - 0,
                            wordsize - 1 - 4 * i - 1,
                            wordsize - 1 - 4 * i - 2,
                            wordsize - 1 - 4 * i - 3,
                            )
            command += "ASSERT(SBOX{}[{}@{}] = 0bin1);\n".format(wordsize // 4-i-1,
                        s_in_4_bit, s_out_4_bit_S)
            command += "ASSERT({1} = (IF {0} = 0bin0000 " \
                                            "THEN 0bin0 " \
                                      "ELSE 0bin1 ENDIF));\n".format(
                        s_in_4_bit,
                        "{0}[{1}:{1}]".format(act_flag, wordsize // 4 - 1 - i))

        
        # 3. rot out_G0, out_G1
        rotout_y = rotl(y, self.rot_alpha, wordsize)
        #out_G1_rotbeta  = rotl(out_G1, self.rot_beta,  wordsize)
        command += "ASSERT({} = {});\n".format(rot_y, rotout_y)
        #command += "ASSERT({} = {});\n".format(rot_G1, out_G1_rotbeta)

        # 4. G0 ^ G1 = xor_G
        #command += "ASSERT({} = BVXOR({}, {}));\n".format(xor_G, rot_G0, rot_G1)

        # 4. xor_G PERM to perm_G
        for i in range(wordsize//8):
            command += "ASSERT({0}[4*{1}+3:4*{1}] = {2}[4*{3}+3:4*{3}]);\n".format(
                    perm_G, i, out_S, p[i])

        # 5. perm_G ^ y_in = x_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(rot_y, perm_G, x_out)

        # 6. Weight computation
        sum_w_i = stpcommands.getWeightString([act_flag], wordsize // 4, 0, w)
        sum_w_i += '\n'
        command += sum_w_i

        stp_file.write(command)
        return

def SBOX_ACT_ASSERT(self, stp_file):
        command = "SBOX0 : ARRAY BITVECTOR(8) OF BITVECTOR(1);\n"
        command = "SBOX1 : ARRAY BITVECTOR(8) OF BITVECTOR(1);\n"
        command = "SBOX2 : ARRAY BITVECTOR(8) OF BITVECTOR(1);\n"
        command = "SBOX3 : ARRAY BITVECTOR(8) OF BITVECTOR(1);\n"
        command = "SBOX4 : ARRAY BITVECTOR(8) OF BITVECTOR(1);\n"
        command = "SBOX5 : ARRAY BITVECTOR(8) OF BITVECTOR(1);\n"
        command = "SBOX6 : ARRAY BITVECTOR(8) OF BITVECTOR(1);\n"
        command = "SBOX7 : ARRAY BITVECTOR(8) OF BITVECTOR(1);\n"

        DDT0 = ddt.ddt0
        DDT1 = ddt.ddt1
        DDT2 = ddt.ddt2
        DDT3 = ddt.ddt3
        DDT4 = ddt.ddt4
        DDT5 = ddt.ddt5
        DDT6 = ddt.ddt6
        DDT7 = ddt.ddt7
        for i in range(16):
            for j in range(16):
                if DDT0[i][j] != 0:
                    command += "ASSERT(SBOX0[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                else:
                    command += "ASSERT(SBOX0[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                if DDT1[i][j] != 0:
                    command += "ASSERT(SBOX1[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                else:
                    command += "ASSERT(SBOX1[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                if DDT2[i][j] != 0:
                    command += "ASSERT(SBOX2[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                else:
                    command += "ASSERT(SBOX2[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                if DDT3[i][j] != 0:
                    command += "ASSERT(SBOX3[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                else:
                    command += "ASSERT(SBOX3[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                if DDT4[i][j] != 0:
                    command += "ASSERT(SBOX4[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                else:
                    command += "ASSERT(SBOX4[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                if DDT5[i][j] != 0:
                    command += "ASSERT(SBOX5[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                else:
                    command += "ASSERT(SBOX5[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                if DDT6[i][j] != 0:
                    command += "ASSERT(SBOX6[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                else:
                    command += "ASSERT(SBOX6[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                if DDT7[i][j] != 0:
                    command += "ASSERT(SBOX7[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
                else:
                    command += "ASSERT(SBOX7[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:04b}".format(j))
        
        stp_file.write(command)
        return


















            
