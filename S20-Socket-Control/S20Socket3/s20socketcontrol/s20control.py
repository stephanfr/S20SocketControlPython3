
import socket
import threading
import queue
import time
import enum


#
#    Start with some constants describing the interface to the S20 Socket
#


PROBE_ADDRESS = ("8.8.8.8", 80)                                #    Google's DNS server, port 80 - nothing should happen...


S20_UDP_PORT = 10000

BROADCAST_ADDRESS = ( '<broadcast>', S20_UDP_PORT )
RECEIVE_ADDRESS = ( '', S20_UDP_PORT )


DEFAULT_SOCKET_READ_TIMEOUT = 2.0
LISTENER_JOIN_TIMEOUT = 10.0
SUBSCRIPTION_TIMEOUT = 60


GLOBAL_SOCKET_DISCOVERY_MESSAGE = bytearray.fromhex("68 64 00 06 71 61")

MAC_ADDRESS_SUBSTITUION = bytearray.fromhex("00 00 00 00 00 00")

SOCKET_SUBSCRIBE_MESSAGE = bytearray.fromhex("68 64 00 1E 63 6C 00 00 00 00 00 00 20 20 20 20 20 20 00 00 00 00 00 00 20 20 20 20 20 20")
SOCKET_POWER_ON_MESSAGE = bytearray.fromhex("68 64 00 17 64 63 00 00 00 00 00 00 20 20 20 20 20 20 00 00 00 00 01")
SOCKET_POWER_OFF_MESSAGE = bytearray.fromhex("68 64 00 17 64 63 00 00 00 00 00 00 20 20 20 20 20 20 00 00 00 00 00")
SOCKET_DATA_MESSAGE = bytearray.fromhex("68 64 00 1D 72 74 00 00 00 00 00 00 20 20 20 20 20 20 00 00 00 00 04 00 00 00 00 00 00")


GLOBAL_DISCOVERY_TOKEN = bytearray.fromhex("71 61")
SINGLE_DISCOVERY_TOKEN = bytearray.fromhex("71 67")
SUBSCRIBE_TOKEN = bytearray.fromhex("63 6C")
SWITCH_STATE_CHANGED_TOKEN = bytearray.fromhex("73 66")
SOCKET_DATA_TOKEN = bytearray.fromhex("72 74")




#
#    Helper Functions
#

def format_as_mac( macAddress ):
    macInHex = macAddress.hex()
    return( ':'.join(macInHex[i:i+2] for i in range(0,12,2)) )

def format_as_ip( ipAddress ):
    return( ipAddress[0] + ":" + str(ipAddress[1]) )


#
#    Enumerations
#

class S20ResponseType(enum.Enum):
    GLOBAL_DISCOVERY = 1
    SINGLE_DISCOVERY = 2
    SUBSCRIBE = 3
    SWITCH_STATE_CHANGED = 4
    SOCKET_DATA = 5


class S20SwitchState(enum.Enum):
    ON = 1
    OFF = 2
    


#
#    Some functions to decode elements of a raw response and return
#        the appropriate enumeration value.
#

def decode_s20_response_type(response):
    
    commandToken = response[4:6]
  
    if( commandToken == GLOBAL_DISCOVERY_TOKEN ) :
        return( S20ResponseType.GLOBAL_DISCOVERY )
    elif( commandToken == SINGLE_DISCOVERY_TOKEN ) :
        return( S20ResponseType.SINGLE_DISCOVERY )
    elif( commandToken == SUBSCRIBE_TOKEN ) :
        return( S20ResponseType.SUBSCRIBE )
    elif( commandToken == SWITCH_STATE_CHANGED_TOKEN ) :
        return( S20ResponseType.SWITCH_STATE_CHANGED )
    elif( commandToken == SOCKET_DATA_TOKEN ) :
        return( S20ResponseType.SOCKET_DATA )


    return( None )
    
    
def decode_s20_switch_state(responseState):
    
    if( responseState == 0 ) :
        return( S20SwitchState.OFF )
    
    return( S20SwitchState.ON )

    

#
#    Classes for the different responses.  There is a base class and then
#        descendent classes for specific response types
#

class S20Response :
    
    def __init__(self, command, mac_address, ip_address ):
        self._command = command
        self._mac_address = mac_address
        self._ip_address = ip_address
        
    
    def type(self):
        raise NotImplementedError
    
    def __str__(self):
        raise NotImplementedError
    
    
    def command(self):
        return( self._command )
    
    def mac_address(self):
        return(self._mac_address)

    def ip_address(self):
        return( self._ip_address )
    

class S20GlobalDiscoveryResponse(S20Response) :

    def __init__( self, reply_and_address ):
        super( S20GlobalDiscoveryResponse, self ).__init__( reply_and_address[0][4:7], reply_and_address[0][7:13], reply_and_address[1]  )
        self._switch_state = decode_s20_switch_state( reply_and_address[0][41] )

    def type(self):
        return( S20ResponseType.GLOBAL_DISCOVERY )
    
    def __str__(self):
        return( "Global Discovery Response: " + format_as_mac( self.mac_address() ) + "  " + format_as_ip( self.ipaddress() ) + "  " + self._switch_state.name )
 
    def switch_state(self):
        return( self._switch_state )
   

class S20SingleDiscoveryResponse(S20Response) :

    def __init__( self, reply_and_address ):
        super( S20SingleDiscoveryResponse, self ).__init__( reply_and_address[0][4:7], reply_and_address[0][7:13], reply_and_address[1]  )
        self._switch_state = decode_s20_switch_state( reply_and_address[0][41] )

    def type(self):
        return( S20ResponseType.SINGLE_DISCOVERY )
    
    def __str__(self):
        return( "Single Discovery Response: " + format_as_mac( self.mac_address() ) + "  " + format_as_ip( self.ipaddress() ) + "  " + self._switch_state.name )
    
    def switch_state(self):
        return( self._switch_state )
   

class S20SubscribeResponse(S20Response) :

    def __init__( self, reply_and_address ):
        super( S20SubscribeResponse, self ).__init__( reply_and_address[0][4:7], reply_and_address[0][6:12], reply_and_address[1]  )
        self._switch_state = decode_s20_switch_state( reply_and_address[0][23] )

    def type(self):
        return( S20ResponseType.SUBSCRIBE )
    
    def __str__(self):
        return( "Subscribe Response: " + format_as_mac( self.mac_address() ) + "  " + format_as_ip( self.ipaddress() ) + "  " + self._switch_state.name )
    
    def switch_state(self):
        return( self._switch_state )


class S20SwitchStateChangedResponse(S20Response) :

    def __init__( self, reply_and_address ):
        super( S20SwitchStateChangedResponse, self ).__init__( reply_and_address[0][4:7], reply_and_address[0][6:12], reply_and_address[1]  )
        self._switch_state = decode_s20_switch_state( reply_and_address[0][22] )

    def type(self):
        return( S20ResponseType.SWITCH_STATE_CHANGED )
    
    def __str__(self):
        return( "Power On Response: " + format_as_mac( self.mac_address() ) + "  " + format_as_ip( self.ipaddress() ) + "  " + self._switch_state.name )
    
    def switch_state(self):
        return( self._switch_state )


class S20SocketDataResponse(S20Response) :

    def __init__( self, reply_and_address ):
        super( S20SocketDataResponse, self ).__init__( reply_and_address[0][4:7], reply_and_address[0][6:12], reply_and_address[1]  )
        
        #    Sockets with uninitialized names have 0xff bytes through the entire name block.  Those
        #        bytes cannot be decoded so handle uninitialized socket names as a corner case.
        
        if( reply_and_address[0][70:71] == b'\xff' ) :
            self._name = '**Uninitialized**'
        else :
            self._name = reply_and_address[0][70:86].decode("utf-8").strip()
            
        self._hardware_version = int( reply_and_address[0][88] )
        self._firmware_version = int( reply_and_address[0][92] )
        self._wifi_chipset_version = int( reply_and_address[0][96] )
        

    def type(self):
        return( S20ResponseType.SOCKET_DATA )
    
    def __str__(self):
        return( "Power On Response: " + format_as_mac( self.mac_address() ) + "  " + format_as_ip( self.ipaddress() ) + "  " + self._switch_state.name )
    
    def name(self):
        return( self._name )
    
    def hardware_version(self):
        return( self._hardware_version)
    
    def firmware_version(self):
        return( self._firmware_version)
    
    def wifi_chipset_version(self):
        return( self._wifi_chipset_version)
    


    
#
#    Listener class that runs as a daemon thread.
#

class S20SocketManager :

    _communication_lock = threading.Lock()

    _s20_socket_dictionary = dict()
    
    _global_discovery_queue = queue.Queue()
    
    
    _response_decoder = { S20ResponseType.GLOBAL_DISCOVERY : S20GlobalDiscoveryResponse,
                          S20ResponseType.SINGLE_DISCOVERY : S20SingleDiscoveryResponse,
                          S20ResponseType.SUBSCRIBE : S20SubscribeResponse,
                          S20ResponseType.SWITCH_STATE_CHANGED : S20SwitchStateChangedResponse,
                          S20ResponseType.SOCKET_DATA : S20SocketDataResponse }

                
    def __init__(self):
        self._receive_socket = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        self._receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._receive_socket.settimeout(DEFAULT_SOCKET_READ_TIMEOUT)
        self._receive_socket.bind(( self._get_local_ipaddress(), S20_UDP_PORT ))

        self._send_socket = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        
        self._listening = False
        
        self._listener_thread = threading.Thread(target=self._listen, daemon=True)
        
 
    def _get_local_ipaddress(self):
        probeSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probeSocket.connect( PROBE_ADDRESS )
        return probeSocket.getsockname()[0]
    
    
    def _nextGlobalDiscoveryResponse(self, timeout = DEFAULT_SOCKET_READ_TIMEOUT ) :
        try :
            response = self._global_discovery_queue.get( True, timeout )
        except queue.Empty :
            return None
        else :
            return response



    def _listen(self):
        self._listening = True
        
        while self._listening:
            try :
                response, address = self._receive_socket.recvfrom(1024)
            except socket.timeout :
                pass
            else:
                response_type = decode_s20_response_type(response)

                if( response_type != None ) :
                    decoded_response = self._response_decoder.get( response_type )(( response, address ))
                    
                    if( decoded_response.type() == S20ResponseType.GLOBAL_DISCOVERY ) :
                        self._global_discovery_queue.put_nowait( decoded_response )
                    else :
                        if( decoded_response.mac_address() in self._s20_socket_dictionary ) :
                            self._s20_socket_dictionary[decoded_response.mac_address()]._response_queues[response_type].put_nowait( decoded_response )
                    
        self._listening = False
        self._receive_socket.close()
                
       
        
    def get_lock(self):
        return( self._communication_lock )
    
    
    def sockets(self):
        return( self._s20_socket_dictionary )


    def start_listening(self):
        if not self._listener_thread.is_alive()  :
            self._listener_thread.start()
            self.discover_sockets()


    def stop_listening(self):
        self._listening = False
        self._listener_thread.join(LISTENER_JOIN_TIMEOUT)
        

    def discover_sockets( self ):
    
        with self._communication_lock :
            
            self._global_discovery_queue.queue.clear()
            
            broadcast_socket = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            broadcast_socket.sendto( GLOBAL_SOCKET_DISCOVERY_MESSAGE, BROADCAST_ADDRESS )
            
            global_discovery_response = self._nextGlobalDiscoveryResponse()
            
            while( global_discovery_response != None ) :
                if( not global_discovery_response.mac_address() in self._s20_socket_dictionary ) :
                    self._s20_socket_dictionary[global_discovery_response.mac_address()] = S20Socket( self, global_discovery_response.mac_address(), global_discovery_response.ip_address(), global_discovery_response.switch_state() )
                
                global_discovery_response = self._nextGlobalDiscoveryResponse()
            
        #    We have all the sockets, now fill the socket attributes
                
        for s20_instance in self._s20_socket_dictionary.values() :
            s20_instance._get_socket_data()

        

    def send_message(self, command_message, ip_address ):
        self._send_socket.sendto( command_message, ip_address )
        
        
    def find_socket_by_name(self, name):
        for s20_instance in self._s20_socket_dictionary.values() :
            if s20_instance.name() == name :
                return( s20_instance )
            
        return( None )


    def find_socket_by_ipaddress(self, ip_address):
        for s20_instance in self._s20_socket_dictionary.values() :
            if s20_instance.ip_address()[0] == ip_address :
                return( s20_instance )
            
        return( None )


    def find_socket_by_macaddress(self, mac_address):
        colon_less_mac = bytearray.fromhex(mac_address.replace(':',''))

        for s20_instance in self._s20_socket_dictionary.values() :
            if s20_instance.mac_address() == colon_less_mac :
                return( s20_instance )
            
        return( None )



#
# S20Socket class
#
# Equality for this class is based solely on the MAC address for the S20 socket.
#    Two different instances of the class will be eqaual and have the same hash value
#    if the MAC addresses are the same.
#

class S20Socket :
    
    _response_queues = { S20ResponseType.SINGLE_DISCOVERY : queue.Queue(),
                        S20ResponseType.SUBSCRIBE : queue.Queue(),
                        S20ResponseType.SWITCH_STATE_CHANGED : queue.Queue(),
                        S20ResponseType.SOCKET_DATA : queue.Queue() }

    
    def __init__(self, manager, mac_address, ip_address, switch_state ) :
        self._manager = manager
        self._mac_address = mac_address
        self._ip_address = ip_address
        self._switch_state = switch_state
        self._subscribed = False
        self._time_of_last_subscription = 0
        self._name = ""
        self._hardware_version = -1
        self._firmware_version = -1
        self._wifi_chipset_version = -1
        
    def __hash__(self):
        return( hash( self._mac_address.hex() ))
    
    def __eq__(self, other):
        return( self._mac_address == other._mac_address )
       
    def __str__(self):
        return( "S20 Socket: " + self._name + "  " + format_as_mac( self._mac_address ) + "  " +
                               format_as_ip( self._ip_address ) + "  " +
                               self._switch_state.name + "  " +
                               str( self._hardware_version ) + "  " +
                               str( self._firmware_version ) + "  " + 
                               str( self._wifi_chipset_version ) )
        
        
    def _next_response(self, response_type, timeout = DEFAULT_SOCKET_READ_TIMEOUT):
        desired_queue = self._response_queues.get(response_type);
        try :
            response = desired_queue.get( True, timeout )
        except queue.Empty :
            return None
        else :
            return response

    
    def _subscribe(self):
        
        if self._subscribed :
            if time.time() - self._time_of_last_subscription > SUBSCRIPTION_TIMEOUT :
                self._subscribed = False
        
        if not self._subscribed :

            self._response_queues[S20ResponseType.SUBSCRIBE].queue.clear()
            
            subscribe_message = SOCKET_SUBSCRIBE_MESSAGE.replace(MAC_ADDRESS_SUBSTITUION, self._mac_address, 1)
            
            mac_address_little_endian = self._mac_address[::-1];
            subscribe_message = subscribe_message.replace(MAC_ADDRESS_SUBSTITUION, mac_address_little_endian )
            
            self._manager.send_message( subscribe_message, self._ip_address )
    
            subscribe_response = self._next_response( S20ResponseType.SUBSCRIBE )
            
            while( subscribe_response != None ) :
                self._subscribed = True
                self._time_of_last_subscription = time.time()
                
                subscribe_response = self._next_response( S20ResponseType.SUBSCRIBE )
                
        return( self._subscribed )
        
     
    def _get_socket_data(self):
        
        with self._manager.get_lock() :
            
            self._subscribe()
            
            self._response_queues[S20ResponseType.SWITCH_STATE_CHANGED]
            
            data_message = SOCKET_DATA_MESSAGE.replace(MAC_ADDRESS_SUBSTITUION, self._mac_address, 1)
            
            self._manager.send_message( data_message, self._ip_address )
    
            data_response = self._next_response( S20ResponseType.SOCKET_DATA )
        
            while( data_response != None ) :
                
                self._name = data_response.name()
                self._hardware_version = data_response.hardware_version()
                self._firmware_version = data_response.firmware_version()
                self._wifi_chipset_version = data_response.wifi_chipset_version()
                
                data_response = self._next_response( S20ResponseType.SOCKET_DATA )
   
    
    def mac_address(self):
        return( self._mac_address )
    
    def ip_address(self):
        return( self._ip_address )
    
    def name(self):
        return( self._name )
    
    
    def power_on(self):
        
        with self._manager.get_lock() :
            
            self._subscribe()
            
            self._response_queues[S20ResponseType.SWITCH_STATE_CHANGED]
            
            power_on_message = SOCKET_POWER_ON_MESSAGE.replace(MAC_ADDRESS_SUBSTITUION, self._mac_address, 1)
            
            self._manager.send_message( power_on_message, self._ip_address )
    
            power_on_response = self._next_response( S20ResponseType.SWITCH_STATE_CHANGED )
        
            while( power_on_response != None ) :
                power_on_response = self._next_response( S20ResponseType.SWITCH_STATE_CHANGED )
        
    
    def power_off(self):
        
        with self._manager.get_lock() :
            
            self._subscribe()
            
            self._response_queues[S20ResponseType.SWITCH_STATE_CHANGED]
            
            power_on_message = SOCKET_POWER_OFF_MESSAGE.replace(MAC_ADDRESS_SUBSTITUION, self._mac_address, 1)
            
            self._manager.send_message( power_on_message, self._ip_address )
    
            power_off_response = self._next_response( S20ResponseType.SWITCH_STATE_CHANGED )
        
            while( power_off_response != None ) :
                power_off_response = self._next_response( S20ResponseType.SWITCH_STATE_CHANGED )
        
         




