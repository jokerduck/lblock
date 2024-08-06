'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import GenPerm as GenPerm
from ciphers import SatConstraints as SatConstraints

from parser.stpcommands import getStringLeftRotate as rotl


class Cipher(AbstractCipher):
    """
    Represents the linear behaviour of BAT nibble and can be used
    to find linear characteristics for the given parameters.
    """

    name = "bat_integral"
    rot_alpha = 0
    rot_beta = 4
    PERM = []

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y',
                'x0ls', 'x1ls',

                'inI0F0',
                'noutI0F0',
                'outI0F0',
                'inI0F1',
                'noutI0F1',

                'inI1F0',
                'noutI1F0',
                'outI1F0',
                'inI1F1',
                'noutI1F1',
                'outI1F1',

                ]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for BAT integral with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds   = parameters["rounds"]
        if wordsize == 32:
            p = [7, 4, 1, 6, 3, 0, 5, 2]
        elif wordsize == 64:
            p = [14, 15, 8, 9, 2, 3, 12, 13, 6, 7, 0, 1, 10, 11, 4, 5]
        else:
            raise Exception("Wrong wordsize!")
        self.PERM = GenPerm.GenNibblePerms(wordsize, p)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP: BAT integral\n"
                      "% w={} alpha={} beta={}\n"
                      "% rounds={}\n\n".format(wordsize,
                                               self.rot_alpha,
                                               self.rot_beta,
                                               rounds,
                                               ))
            stp_file.write(header)

            # Setup variables
            # x = left, y = right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            x0_leftshift = ["x0ls{}".format(i) for i in range(rounds)]
            x1_leftshift = ["x1ls{}".format(i) for i in range(rounds)]
            copy0 = ["copy0{}".format(i) for i in range(rounds)]
            gout = ["gout{}".format(i) for i in range(rounds + 1)]

            nor_in0_i0_r0 = ["nin0I0F0{}".format(i) for i in range(rounds)]
            nor_in1_i0_r0 = ["nin1I0F0{}".format(i) for i in range(rounds)]
            nor_in0_i0_r1 = ["nin0I0F1{}".format(i) for i in range(rounds)]
            nor_in1_i0_r1 = ["nin1I0F1{}".format(i) for i in range(rounds)]

            nor_in0_i1_r0 = ["nin0I1F0{}".format(i) for i in range(rounds)]
            nor_in1_i1_r0 = ["nin1I1F0{}".format(i) for i in range(rounds)]
            nor_in0_i1_r1 = ["nin0I1F1{}".format(i) for i in range(rounds)]
            nor_in1_i1_r1 = ["nin1I1F1{}".format(i) for i in range(rounds)]

            nor_out_i0_r0 = ["noutI0F0{}".format(i) for i in range(rounds)]
            nor_out_i0_r1 = ["noutI0F1{}".format(i) for i in range(rounds)]
            nor_out_i1_r0 = ["noutI1F0{}".format(i) for i in range(rounds)]
            nor_out_i1_r1 = ["noutI1F1{}".format(i) for i in range(rounds)]

            in_at_i0_r0 = ["inI0F0{}".format(i) for i in range(rounds)]
            out_at_i0_r0 = ["outI0F0{}".format(i) for i in range(rounds)]
            in_at_i0_r1 = ["inI0F1{}".format(i) for i in range(rounds)]
            out_at_i0_r1 = ["outI0F1{}".format(i) for i in range(rounds)]

            in_at_i1_r0 = ["inI1F0{}".format(i) for i in range(rounds)]
            out_at_i1_r0 = ["outI1F0{}".format(i) for i in range(rounds)]
            in_at_i1_r1 = ["inI1F1{}".format(i) for i in range(rounds)]
            out_at_i1_r1 = ["outI1F1{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, x0_leftshift, wordsize)
            stpcommands.setupVariables(stp_file, x1_leftshift, wordsize)

            stpcommands.setupVariables(stp_file, copy0, wordsize)
            stpcommands.setupVariables(stp_file, gout, wordsize)

            stpcommands.setupVariables(stp_file, nor_in0_i0_r0, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_in1_i0_r0, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_in0_i0_r1, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_in1_i0_r1, wordsize // 4)

            stpcommands.setupVariables(stp_file, nor_in0_i1_r0, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_in1_i1_r0, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_in0_i1_r1, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_in1_i1_r1, wordsize // 4)

            stpcommands.setupVariables(stp_file, nor_out_i0_r0, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_out_i0_r1, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_out_i1_r0, wordsize // 4)
            stpcommands.setupVariables(stp_file, nor_out_i1_r1, wordsize // 4)

            stpcommands.setupVariables(stp_file, in_at_i0_r0, wordsize)
            stpcommands.setupVariables(stp_file, out_at_i0_r0, wordsize)
            stpcommands.setupVariables(stp_file, in_at_i0_r1, wordsize)
            stpcommands.setupVariables(stp_file, out_at_i0_r1, wordsize)

            stpcommands.setupVariables(stp_file, in_at_i1_r0, wordsize)
            stpcommands.setupVariables(stp_file, out_at_i1_r0, wordsize)
            stpcommands.setupVariables(stp_file, in_at_i1_r1, wordsize)
            stpcommands.setupVariables(stp_file, out_at_i1_r1, wordsize)

            for i in range(rounds):
                self.setupSimonRound(stp_file,
                                     x[i], y[i],
                                     x0_leftshift[i], x1_leftshift[i],
                                     copy0[i], gout[i],
                                     x[i+1], y[i+1],

                                     nor_in0_i0_r0[i],
                                     nor_in1_i0_r0[i],
                                     nor_in0_i0_r1[i],
                                     nor_in1_i0_r1[i],

                                     nor_in0_i1_r0[i],
                                     nor_in1_i1_r0[i],
                                     nor_in0_i1_r1[i],
                                     nor_in1_i1_r1[i],

                                     nor_out_i0_r0[i],
                                     nor_out_i0_r1[i],
                                     nor_out_i1_r0[i],
                                     nor_out_i1_r1[i],

                                     in_at_i0_r0[i],
                                     out_at_i0_r0[i],
                                     in_at_i0_r1[i],
                                     out_at_i0_r1[i],

                                     in_at_i1_r0[i],
                                     out_at_i1_r0[i],
                                     in_at_i1_r1[i],
                                     out_at_i1_r1[i],
                                     wordsize,
                                    )

            # No all zero characteristic
            #  stpcommands.assertNonZero(stp_file, [x[0], y[0]], wordsize)

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

    def setupSimonRound(self, stp_file,
                        x_in, y_in,
                        x0_leftshift, x1_leftshift,
                        copy0, gout,
                        x_out, y_out,

                        nor_in0_i0_r0,
                        nor_in1_i0_r0,
                        nor_in0_i0_r1,
                        nor_in1_i0_r1,

                        nor_in0_i1_r0,
                        nor_in1_i1_r0,
                        nor_in0_i1_r1,
                        nor_in1_i1_r1,

                        nor_out_i0_r0,
                        nor_out_i0_r1,
                        nor_out_i1_r0,
                        nor_out_i1_r1,

                        in_at_i0_r0,
                        out_at_i0_r0,
                        in_at_i0_r1,
                        out_at_i0_r1,

                        in_at_i1_r0,
                        out_at_i1_r0,
                        in_at_i1_r1,
                        out_at_i1_r1,
                        wordsize,
                       ):
        """
        Model for differential behaviour of one round
        """
        command = ""

        # 1.Copy left
        # copy0
        for i in range(wordsize):
            x = "{0}[{1}:{1}]".format(x_in, wordsize - 1 - i)
            y = "{0}[{1}:{1}]".format(x0_leftshift, wordsize - 1 - i)
            z = "{0}[{1}:{1}]".format(copy0, wordsize - 1 - i)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
        # copy1
        for i in range(wordsize):
            x = "{0}[{1}:{1}]".format(copy0, wordsize - 1 - i)
            y = "{0}[{1}:{1}]".format(x1_leftshift, wordsize - 1 - i)
            z = "{0}[{1}:{1}]".format(y_out, wordsize - 1 - i)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)

        # 2. Split bit
        x_in_rotalpha = rotl(x0_leftshift, self.rot_alpha, wordsize)
        x_in_rotbeta = rotl(x1_leftshift, self.rot_beta, wordsize)
        command += "ASSERT({} = {});\n".format(in_at_i0_r0, x_in_rotalpha)
        command += "ASSERT({} = {});\n".format(in_at_i1_r0, x_in_rotbeta)

        # 3. Assert Two branch
        command += self.getBranchByIndex(
                         nor_in0_i0_r0,
                         nor_in1_i0_r0,
                         nor_in0_i0_r1,
                         nor_in1_i0_r1,

                         nor_out_i0_r0,
                         nor_out_i0_r1,

                         in_at_i0_r0,
                         out_at_i0_r0,
                         in_at_i0_r1,
                         out_at_i0_r1,
                         wordsize
                )
        command += self.getBranchByIndexVice(
                         nor_in0_i1_r0,
                         nor_in1_i1_r0,
                         nor_in0_i1_r1,
                         nor_in1_i1_r1,

                         nor_out_i1_r0,
                         nor_out_i1_r1,

                         in_at_i1_r0,
                         out_at_i1_r0,
                         in_at_i1_r1,
                         out_at_i1_r1,
                         wordsize
                )

        # 4. Assert XORS
        # xor0
        for i in range(wordsize):
            x = "{0}[{1}:{1}]".format(out_at_i0_r1, wordsize - 1 - i)
            y = "{0}[{1}:{1}]".format(out_at_i1_r1, wordsize - 1 - i)
            z = "{0}[{1}:{1}]".format(gout, wordsize - 1 - i)
            command += SatConstraints.GenXorBitConstraints(x, y, z)
        # xor1
        for i in range(wordsize):
            x = "{0}[{1}:{1}]".format(gout, wordsize - 1 - i)
            y = "{0}[{1}:{1}]".format(y_in, wordsize - 1 - i)
            z = "{0}[{1}:{1}]".format(x_out, wordsize - 1 - i)
            command += SatConstraints.GenXorBitConstraints(x, y, z)

        stp_file.write(command)
        return

    def getBranchByIndex(self,
                         nor_in0_i_r0,
                         nor_in1_i_r0,
                         nor_in0_i_r1,
                         nor_in1_i_r1,

                         nor_out_i_r0,
                         nor_out_i_r1,

                         in_at_i_r0,
                         out_at_i_r0,
                         in_at_i_r1,
                         out_at_i_r1,
                         wordsize
                        ):
        command = '% G0\n'

        # 1 AND at r0
        for i in range(wordsize // 4):
            # copy nor_in0_i_r0
            x = "{0}[{1}:{1}]".format(in_at_i_r0, wordsize - 4 * i - 1 - 0)
            y = "{0}[{1}:{1}]".format(out_at_i_r0, wordsize - 4 * i - 1 - 0)
            z = "{0}[{1}:{1}]".format(nor_in0_i_r0, wordsize // 4 - i - 1)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
            # copy nor_in1_i_r0
            x = "{0}[{1}:{1}]".format(in_at_i_r0, wordsize - 4 * i - 1 - 1)
            y = "{0}[{1}:{1}]".format(out_at_i_r0, wordsize - 4 * i - 1 - 1)
            z = "{0}[{1}:{1}]".format(nor_in1_i_r0, wordsize // 4 - i - 1)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
            # AND
            x = "{0}[{1}:{1}]".format(nor_in0_i_r0, wordsize // 4 - i - 1)
            y = "{0}[{1}:{1}]".format(nor_in1_i_r0, wordsize // 4 - i - 1)
            z = "{0}[{1}:{1}]".format(nor_out_i_r0, wordsize // 4 - i - 1)
            command += SatConstraints.GenAndBitConstraints(x, y, z)
            # xor
            x = "{0}[{1}:{1}]".format(nor_out_i_r0, wordsize // 4 - i - 1)
            y = "{0}[{1}:{1}]".format(in_at_i_r0, wordsize - 4 * i - 1 - 3)
            z = "{0}[{1}:{1}]".format(out_at_i_r0, wordsize - 4 * i - 1 - 3)
            command += SatConstraints.GenXorBitConstraints(x, y, z)
            # direct down
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                    out_at_i_r0, wordsize - 4 * i - 1 - 2,
                    in_at_i_r0, wordsize - 4 * i - 1 - 2,
                    )

        # 2 Perm
        for i in range(wordsize):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                        in_at_i_r1, self.PERM[i],
                        out_at_i_r0, i)

        # 3 AND at r1
        for i in range(wordsize // 4):
            # copy nor_in0_i_r1
            x = "{0}[{1}:{1}]".format(in_at_i_r1, wordsize - 4 * i - 1 - 3)
            y = "{0}[{1}:{1}]".format(out_at_i_r1, wordsize - 4 * i - 1 - 3)
            z = "{0}[{1}:{1}]".format(nor_in0_i_r1, wordsize // 4 - i - 1)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
            # copy nor_in1_i_r1
            x = "{0}[{1}:{1}]".format(in_at_i_r1, wordsize - 4 * i - 1 - 2)
            y = "{0}[{1}:{1}]".format(out_at_i_r1, wordsize - 4 * i - 1 - 2)
            z = "{0}[{1}:{1}]".format(nor_in1_i_r1, wordsize // 4 - i - 1)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
            # AND
            x = "{0}[{1}:{1}]".format(nor_in0_i_r1, wordsize // 4 - i - 1)
            y = "{0}[{1}:{1}]".format(nor_in1_i_r1, wordsize // 4 - i - 1)
            z = "{0}[{1}:{1}]".format(nor_out_i_r1, wordsize // 4 - i - 1)
            command += SatConstraints.GenAndBitConstraints(x, y, z)
            # xor
            x = "{0}[{1}:{1}]".format(nor_out_i_r1, wordsize // 4 - i - 1)
            y = "{0}[{1}:{1}]".format(in_at_i_r1, wordsize - 4 * i - 1 - 0)
            z = "{0}[{1}:{1}]".format(out_at_i_r1, wordsize - 4 * i - 1 - 0)
            command += SatConstraints.GenXorBitConstraints(x, y, z)
            # direct down
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                    out_at_i_r1, wordsize - 4 * i - 1 - 1,
                    in_at_i_r1, wordsize - 4 * i - 1 - 1,
                    )

        return command

    def getBranchByIndexVice(self,
                             nor_in0_i_r0,
                             nor_in1_i_r0,
                             nor_in0_i_r1,
                             nor_in1_i_r1,

                             nor_out_i_r0,
                             nor_out_i_r1,

                             in_at_i_r0,
                             out_at_i_r0,
                             in_at_i_r1,
                             out_at_i_r1,
                             wordsize
                        ):
        command = '%% G1\n'

        # 1 AND at r0
        for i in range(wordsize // 4):
            # copy nor_in0_i_r0
            x = "{0}[{1}:{1}]".format(in_at_i_r0, wordsize - 4 * i - 1 - 0)
            y = "{0}[{1}:{1}]".format(out_at_i_r0, wordsize - 4 * i - 1 - 0)
            z = "{0}[{1}:{1}]".format(nor_in0_i_r0, wordsize // 4 - i - 1)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
            # copy nor_in1_i_r0
            x = "{0}[{1}:{1}]".format(in_at_i_r0, wordsize - 4 * i - 1 - 2)
            y = "{0}[{1}:{1}]".format(out_at_i_r0, wordsize - 4 * i - 1 - 2)
            z = "{0}[{1}:{1}]".format(nor_in1_i_r0, wordsize // 4 - i - 1)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
            # AND
            x = "{0}[{1}:{1}]".format(nor_in0_i_r0, wordsize // 4 - i - 1)
            y = "{0}[{1}:{1}]".format(nor_in1_i_r0, wordsize // 4 - i - 1)
            z = "{0}[{1}:{1}]".format(nor_out_i_r0, wordsize // 4 - i - 1)
            command += SatConstraints.GenAndBitConstraints(x, y, z)
            # xor
            x = "{0}[{1}:{1}]".format(nor_out_i_r0, wordsize // 4 - i - 1)
            y = "{0}[{1}:{1}]".format(in_at_i_r0, wordsize - 4 * i - 1 - 1)
            z = "{0}[{1}:{1}]".format(out_at_i_r0, wordsize - 4 * i - 1 - 1)
            command += SatConstraints.GenXorBitConstraints(x, y, z)
            # direct down
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                    out_at_i_r0, wordsize - 4 * i - 1 - 3,
                    in_at_i_r0, wordsize - 4 * i - 1 - 3,
                    )

        # 2 Perm
        for i in range(wordsize):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                        in_at_i_r1, self.PERM[i],
                        out_at_i_r0, i)

        # 3 AND at r1
        for i in range(wordsize // 4):
            # copy nor_in0_i_r1
            x = "{0}[{1}:{1}]".format(in_at_i_r1, wordsize - 4 * i - 1 - 3)
            y = "{0}[{1}:{1}]".format(out_at_i_r1, wordsize - 4 * i - 1 - 3)
            z = "{0}[{1}:{1}]".format(nor_in0_i_r1, wordsize // 4 - i - 1)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
            # copy nor_in1_i_r1
            x = "{0}[{1}:{1}]".format(in_at_i_r1, wordsize - 4 * i - 1 - 1)
            y = "{0}[{1}:{1}]".format(out_at_i_r1, wordsize - 4 * i - 1 - 1)
            z = "{0}[{1}:{1}]".format(nor_in1_i_r1, wordsize // 4 - i - 1)
            command += SatConstraints.GenCopyBitConstraints(x, y, z)
            # AND
            x = "{0}[{1}:{1}]".format(nor_in0_i_r1, wordsize // 4 - i - 1)
            y = "{0}[{1}:{1}]".format(nor_in1_i_r1, wordsize // 4 - i - 1)
            z = "{0}[{1}:{1}]".format(nor_out_i_r1, wordsize // 4 - i - 1)
            command += SatConstraints.GenAndBitConstraints(x, y, z)
            # xor
            x = "{0}[{1}:{1}]".format(nor_out_i_r1, wordsize // 4 - i - 1)
            y = "{0}[{1}:{1}]".format(in_at_i_r1, wordsize - 4 * i - 1 - 2)
            z = "{0}[{1}:{1}]".format(out_at_i_r1, wordsize - 4 * i - 1 - 2)
            command += SatConstraints.GenXorBitConstraints(x, y, z)
            # direct down
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                    out_at_i_r1, wordsize - 4 * i - 1 - 0,
                    in_at_i_r1, wordsize - 4 * i - 1 - 0,
                    )

        return command
