'''
Created on Mar 1, 2019
@author: Shawn
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import GenPerm as GenPerm
from ciphers import ssb_ddt

from parser.stpcommands import getStringLeftRotate as rotl

class Cipher(AbstractCipher):
    """
    Represents the differential behaviour of sand and can be used
    to find differential characteristics for the given parameters.
    """

    name = "intesand"
    rot_alpha = 0
    rot_beta = 4
    PERM = []

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y',
                "outG0", "outG1",
                "rotG0", "rotG1",
                "xorG", "permG",
                "sumw",
                ]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for sand diff pattern with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds   = parameters["rounds"]
        #weight   = parameters["sweight"]
        if wordsize == 32:
            p = [7, 4, 1, 6, 3, 0, 5, 2]
        elif wordsize == 64:
            p = [14, 15, 8, 9, 2, 3, 12, 13, 6, 7, 0, 1, 10, 11, 4, 5]
        else:
            raise Exception("Wrong wordsize!")
        self.PERM = GenPerm.GenNibblePerms(wordsize, p)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP: sand diff actsbox\n"
                      "% w = {} alpha = {} beta = {}\n"
                      "% rounds = {}\n\n".format(
                        wordsize,
                        self.rot_alpha, self.rot_beta,
                        rounds))
            stp_file.write(header)

            # Setup variables
            # x as left, y as right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            in_G=["inG{}".format(i) for i in range(rounds)]
            in_G0=["inG0{}".format(i) for i in range(rounds)]
            in_G0=["inG1{}".format(i) for i in range(rounds)]
            rot_G0  = ["rotG0{}".format(i) for i in range(rounds)]
            rot_G1  = ["rotG1{}".format(i) for i in range(rounds)]
            and_G0  = ["andG0{}".format(i) for i in range(rounds)]
            and_G1  = ["andG1{}".format(i) for i in range(rounds)]
            xor_G0  = ["xorG0{}".format(i) for i in range(rounds)]
            xor_G1  = ["xorG1{}".format(i) for i in range(rounds)]
            befp_G  = ["befpG{}".format(i) for i in range(rounds)]
            perm_G  = ["permG{}".format(i) for i in range(rounds)]

            #out_z=["outz{}".format(i) for i in range(2)]
            # w = weight
            #w = ["sumw{}".format(i) for i in range(rounds)]
            #act_flag = ["actflag{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, in_G, wordsize)
            #stpcommands.setupVariables(stp_file, out_z, wordsize//2)
            #stpcommands.setupVariables(stp_file, "sumz", wordsize//2)
            stpcommands.setupVariables(stp_file, out_G0, wordsize)
            stpcommands.setupVariables(stp_file, out_G1, wordsize)
            stpcommands.setupVariables(stp_file, and_G0, wordsize)
            stpcommands.setupVariables(stp_file, and_G1, wordsize)
            stpcommands.setupVariables(stp_file, xor_G0, wordsize)
            stpcommands.setupVariables(stp_file, xor_G1, wordsize)
            stpcommands.setupVariables(stp_file, befp_G, wordsize)
            stpcommands.setupVariables(stp_file, perm_G, wordsize)
            #stpcommands.setupVariables(stp_file, w, 16)
            #stpcommands.setupVariables(stp_file, act_flag, wordsize // 4)
            stpcommand.getWeight(["x{}".format(rounds-1),"y{}".format(rounds-1)],wordsize)
            #stpcommands.setupWeightComputationSum(stp_file, weight, w, 16)
            command="ASSERT(x0[0:0] = 0bin0);\n"
            command+="ASSERT(y0[0:0] = 0bin1);\n"
            for i in range(1,32):
                command+="ASSERT(x0[{}:{}] = 0bin1);\n".format(i)
                command+="ASSERT(y0[{}:{}] = 0bin1);\n".format(i)
            #self.SBOX_ACT_ASSERT(stp_file)

            for i in range(rounds):
                self.setupRound(stp_file,
                                     x[i], y[i],
                                     x[i+1], y[i+1],
                                     and_G0[i], and_G1[i],
                                     xor_G0[i], xor_G1[i],
                                     rot_G0[i],rot_G1[i],
                                     befp_G[i], perm_G[i],
                                     wordsize)

            # No all zero characteristic
            #stpcommands.assertNonZero(stp_file, [x[0], y[0]], wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupRound(self,
                        stp_file,
                        x_in, y_in,
                        x_out, y_out,
                        in_G,in_G0,inG1,
                        and_G0, and_G1,
                        xor_G0, xor_G1,
                        rot_G0,rot_G1,
                        befp_G, perm_G,
                        wordsize):
        """
        Model for differential behaviour of one round
        """
        command = ""

        # 1. y_out = x_in
        command += "ASSERT({0} | NOT({1}));\n".format(x_in, y_out)
        command += "ASSERT({0} | NOT({1});\n".format(x_in, in_G)
        command += "ASSERT(NOT({0}) | {1} | {2});\n".format(x_in, y_out,in_G)
        command += "ASSERT(NOT({0}) |NOT({1}) |NOT({1}) );\n".format(x_in, y_out,in_G)

        command += "ASSERT({0} | NOT({1}));\n".format(in_G, in_G0)
        command += "ASSERT({0} | NOT({1});\n".format(in_G, in_G1)
        command += "ASSERT(NOT({0}) | {1} | {2});\n".format(in_G, in_G0,in_G1)
        command += "ASSERT(NOT({0}) |NOT({1}) |NOT({1}) );\n".format(in_G, in_G0,in_G1)
        

        # 2. pass SSb: x -> out_G0, out_G1
        for i in range(wordsize // 4):
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(and_G0,i*4,in_G0,i*4+3)
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(and_G0,i*4,in_G0,i*4+2)
            command+="ASSERT(NOT({0}[{1}:{1}])|{2}[{3}:{3}]);\n".format(and_G0,i*4,in_G0,i*4+2)
            command+="ASSERT(NOT({0}[{1}:{1}])|NOT({2}[{3}:{3}]));\n".format(and_G0,i*4,in_G0,i*4+3)
            
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(and_G1,i*4+2,in_G1,i*4+3)
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(and_G1,i*4+2,in_G1,i*4+1)
            command+="ASSERT(NOT({0}[{1}:{1}])|{2}[{3}:{3}]);\n".format(and_G1,i*4+2,in_G1,i*4+1)
            command+="ASSERT(NOT({0}[{1}:{1}])|NOT({2}[{3}:{3}]));\n".format(and_G1,i*4+2,in_G1,i*4+3)
            
        for i in range(wordsize // 4):
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(xor_G0,i*4,and_G0,i*4)
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(xor_G0,i*4,in_G0,i*4)
            command+="ASSERT(NOT({0}[{1}:{1}])|{2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(xor_G0,i*4,and_G0,i*4,in_G0,i*4)
            command+="ASSERT(NOT({0}[{1}:{1}])|NOT({2}[{3}:{3}])|NOT({4}[{5}:{5}]));\n".format(xor_G0,i*4,and_G0,i*4,in_G0,i*4)
            
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(xor_G1,i*4+2,and_G1,i*4+2)
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(xor_G1,i*4+2,in_G1,i*4+2)
            command+="ASSERT(NOT({0}[{1}:{1}])|{2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(xor_G1,i*4+2,and_G1,i*4+2,in_G1,i*4+2)
            command+="ASSERT(NOT({0}[{1}:{1}])|NOT({2}[{3}:{3}])|NOT({4}[{5}:{5}]));\n".format(xor_G1,i*4+2,and_G1,i*4+2,in_G1,i*4+2)

        for i in range(wordsize // 4):
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(and_G0,i*4+3,xor_G0,i*4)
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(and_G0,i*4+3,in_G0,i*4+1)
            command+="ASSERT(NOT({0}[{1}:{1}])|{2}[{3}:{3}]);\n".format(and_G0,i*4+3,xor_G0,i*4)
            command+="ASSERT(NOT({0}[{1}:{1}])|NOT({2}[{3}:{3}]));\n".format(and_G0,i*4+3,in_G0,i*4+1)
            
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(and_G1,i*4+1,xor_G1,i*4+2)
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(and_G1,i*4+1,in_G1,i*4)
            command+="ASSERT(NOT({0}[{1}:{1}])|{2}[{3}:{3}]);\n".format(and_G1,i*4+1,xor_G1,i*4+2)
            command+="ASSERT(NOT({0}[{1}:{1}])|NOT({2}[{3}:{3}]));\n".format(and_G1,i*4+1,in_G1,i*4)
            
        for i in range(wordsize // 4):
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(xor_G0,i*4+3,and_G0,i*4+3)
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(xor_G0,i*4+3,in_G0,i*4+3)
            command+="ASSERT(NOT({0}[{1}:{1}])|{2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(xor_G0,i*4+3,and_G0,i*4+3,in_G0,i*4+3)
            command+="ASSERT(NOT({0}[{1}:{1}])|NOT({2}[{3}:{3}])|NOT({4}[{5}:{5}]));\n".format(xor_G0,i*4+3,and_G0,i*4+3,in_G0,i*4+3)
            
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(xor_G1,i*4+1,and_G1,i*4+1)
            command+="ASSERT({0}[{1}:{1}]|NOT({2}[{3}:{3}]));\n".format(xor_G1,i*4+1,in_G1,i*4+1)
            command+="ASSERT(NOT({0}[{1}:{1}])|{2}[{3}:{3}]|{4}[{5}:{5}]);\n".format(xor_G1,i*4+1,and_G1,i*4+1,in_G1,i*4+1)
            command+="ASSERT(NOT({0}[{1}:{1}])|NOT({2}[{3}:{3}])|NOT({4}[{5}:{5}]));\n".format(xor_G1,i*4+1,and_G1,i*4+1,in_G1,i*4+1)
            command+="ASSERT({0}[{1}:{1}] = {2}[{1}:{1}])".format(xor_G0,i*4+2,in_G0,i*4+2)
            command+="ASSERT({0}[{1}:{1}] = {2}[{1}:{1}])".format(xor_G0,i*4+1,in_G0,i*4+1)
            command+="ASSERT({0}[{1}:{1}] = {2}[{1}:{1}])".format(xor_G1,i*4+3,in_G1,i*4+3)
            command+="ASSERT({0}[{1}:{1}] = {2}[{1}:{1}])".format(xor_G1,i*4,in_G1,i*4)

        out_G0_rotalpha = rotl(xor_G0, self.rot_alpha, wordsize)
        out_G1_rotbeta  = rotl(xor_G1, self.rot_beta,  wordsize)
        command += "ASSERT({} = {});\n".format(rot_G0, out_G0_rotalpha)
        command += "ASSERT({} = {});\n".format(rot_G1, out_G1_rotbeta)

        command+="ASSERT({0}|NOT({1}));\n".format(befp_G,rot_G0)
        command+="ASSERT({0}|NOT({1}));\n".format(befp_G,rot_G1)
        command+="ASSERT(NOT({0})|{1}|{2});\n".format(befp_G,rot_G0,rot_G1)
        command+="ASSERT(NOT({0})|NOT({1})|NOT({2}));\n".format(befp_G,rot_G0,rot_G1)

        # 4. xor_G PERM to perm_G
        for i in range(wordsize):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                    perm_G, self.PERM[i], befp_G, i)

        # 5. perm_G ^ y_in = x_out
        command+="ASSERT({0}|NOT({1}));\n".format(x_out,perm_G)
        command+="ASSERT({0}|NOT({1}));\n".format(x_out,y_in)
        command+="ASSERT(NOT({0})|{1}|{2});\n".format(x_out,perm_G,y_in)
        command+="ASSERT(NOT({0})|NOT({1})|NOT({2}));\n".format(x_out,perm_G,y_in)

        # 6. Weight computation
        
        stp_file.write(command)
        return

        return
