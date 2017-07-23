'''
Created on Jul 4, 2017

@author: steve
'''

import sys
import time

import unittest

import s20control



    

class UnitTest(unittest.TestCase):
    
    NUM_SOCKETS = 2
    SOCKET_NAME = "3D Printer"
    SOCKET_IP = "192.168.0.203"
    SOCKET_MAC = "ac:cf:23:8d:45:cc"
    
    

    @classmethod
    def setUpClass(cls):
        UnitTest.s20_manager = s20control.S20SocketManager()
        UnitTest.s20_manager.start_listening()

    @classmethod
    def tearDownClass(cls):
        UnitTest.s20_manager.stop_listening()

    def testFindAllSockets(self):
        assert( len( self.s20_manager.sockets() ) == self.NUM_SOCKETS )

    def testFindByName(self):
        socket = self.s20_manager.find_socket_by_name( self.SOCKET_NAME )    
        socket.power_on()
        time.sleep(10)
        socket.power_off()
        time.sleep(10)
        
    def testFindByIPAddress(self):
        socket = self.s20_manager.find_socket_by_ipaddress( self.SOCKET_IP )    
        socket.power_on()
        time.sleep(10)
        socket.power_off()    
        time.sleep(10)
 
    def testFindByMACAddress(self):
        socket = self.s20_manager.find_socket_by_macaddress( self.SOCKET_MAC )    
        socket.power_on()
        time.sleep(10)
        socket.power_off()
        time.sleep(10)



if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()