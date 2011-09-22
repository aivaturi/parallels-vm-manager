#!/usr/bin/python

__author__  = 'Aditya Ivaturi'
__version__ = '0.1'
__license__ = 'FreeBSD'

import base64
import json
import logging
import logging.handlers
import os
import re
import sys
import subprocess

from bottle import *
import prlsdkapi

"""
@package vmServer
@brief Entry point to vmManager server

In development turn on debug for stacktrace & reload for instantaneous reloads
@code python vmManager.py --debug @endcode
"""
reload = 0
if (len(sys.argv) > 1):
    if (sys.argv[1] == '--debug'):
        debug(True)
        reload = 1
    else:
        debug(False)

# Logging settings for Rome Server
log = logging.getLogger('vmManager')
log.setLevel(logging.DEBUG)
log_file = './prlManager.log'
fileHandler = logging.FileHandler(log_file)
format = logging.Formatter("%(asctime)s %(levelname)s %(filename)s: %(funcName)s() %(lineno)d %(message)s")
fileHandler.setFormatter(format)
log.addHandler(fileHandler)
log.info("Initialized log for vmManager...")

vmManager = None
vmServer = None

class PrlVMManager:
    """ Helper class that will perform operations on Parallels VMs """
    
    def __init__(self):
        # initialize the desktop sdk & login to the Parallels local service
        prlsdkapi.init_desktop_sdk()
        self.server = prlsdkapi.Server()
        try:
            # The call returns a prlsdkapi.Result object on success.
            result = self.server.login_local('', 0, prlsdkapi.prlsdk.consts.PSL_NORMAL_SECURITY).wait()
            log.debug("Logged in to Parallels service")
        except prlsdkapi.PrlSDKError, e:
            sys.exit("Login error: %s" % e)
    
    def __del__(self):
        # Log off and deinitialize the prlsdkapi library.
        self.server.logoff()
        prlsdkapi.deinit_sdk()
            
    def searchVM(self, vm_to_find):
        """
        This method will Obtain a Vm object for the virtual machine specified by
        its name.
        
        @param vm_to_find: Name of the virtual machine to find. Can also be a
                           partial name (starts with the specified string)
        @return <b><Object></b>: Returns a vm object
        """
        log.debug("Entering searchVM()...")
        try:
            result = self.server.get_vm_list().wait()
        except prlsdkapi.PrlSDKError, e:
            log.error("Error: %s" % e)
            log.debug("Exiting searchVM()...")
            return
    
        for i in range(result.get_params_count()):
            vm = result.get_param_by_index(i)
            vm_name = vm.get_name()
            if vm_name.startswith(vm_to_find):
                return vm
        
        log.debug("Exiting searchVM()...")
        return
    
    def _getVMObjects(self):
        # This is an internal method, which obtains the virtual machine list.
        # getVMList is an asynchronous method that returns
        # a prlsdkapi.Result object containing the list of virtual machines.
        log.debug("Entering _getVMObjects()...")
        job = self.server.get_vm_list()
        result = job.wait()
        
        log.debug("Exiting _getVMObjects()...")
        return result
    
    def getVMList(self):
        """
        This method will find all the VMs that are available in Parallels &
        return them as a list.
        
        @return <b><List></b>: List of VM names.
        """
        log.debug("Entering getVMList()...")
        result = self._getVMObjects()
        vm_list = []
        for i in range(result.get_params_count()):
            vm = result.get_param_by_index(i)
            vm_config = vm.get_config()
            vm_list.append(vm_config.get_name())
        
        log.debug(vm_list)
        log.debug("Exiting getVMList()...")
        return vm_list
    
    def getVMListWithInfo(self):
        """
        This method is similar to getVMList but will also gather all the VMs
        relevant information like status, adapter information etc & return them
        as a dictionary. 
        
        @return <b><Dictionary></b>: List of VMs and their relevant information.
        """
        log.debug("Entering getVMListWithInfo()...")
        result = self._getVMObjects()
        
        # Iterate through the Result object parameters.
        # Each parameter is an instance of the prlsdkapi.Vm class.
        vm_list_info = {}
        for i in range(result.get_params_count()):
            vm = result.get_param_by_index(i)
            vm_list_info[i] = self.getVMInfo(vm)
        
        log.debug(vm_list_info)
        log.debug("Exiting getVMListWithInfo()...")
        return vm_list_info
    
    def getVMInfo(self, vm):
        """
        Given a vm object, it'll return all the information about that VM.
        
        @param <b><Object></b>: prlsdapi vm object
        @return <b><Dictionary></b>: VM's information as a dictionary.
        """
        log.debug("Entering getVMInfo()...")
        vm_info = {}
        vm_config = vm.get_config()
        vm_info["name"] = vm_config.get_name()
        vm_info["status"] = self.getVMStatus(vm)
        vm_info["os"] = self.getVMOSInfo(vm)
        vm_info["network"] = self.getVMNetInfo(vm)
        
        log.debug("Exiting getVMInfo()...")
        return vm_info
    
    def getVMStatus(self, vm):
        """
        This method will determine the status of a VM.
        
        @param <b><Object></b>: prlsdapi vm object
        @return <b><String></b>: Status string; either "running", "suspended",
                                 "stopped" or "paused"
        """
        log.debug("Entering getVMStatus()...")
        try:
            state_result = vm.get_state().wait()
        except prlsdkapi.PrlSDKError, e:
            log.erro("Error: %s" % e)
            log.debug("Exiting getVMStatus()...")
            return

        # Now obtain the VmInfo object.
        vm_info = state_result.get_param()

        # Get the virtual machine state code.
        state_code = vm_info.get_state()
        state_desc = "unknown status"

        # Translate the state code into a readable description.
        # For the complete list of states, see the
        # VMS_xxx constants in the Python API Reference guide.
        if state_code == prlsdkapi.prlsdk.consts.VMS_RUNNING:
            state_desc = "running"
        elif state_code == prlsdkapi.prlsdk.consts.VMS_STOPPED:
            state_desc = "stopped"
        elif state_code == prlsdkapi.prlsdk.consts.VMS_PAUSED:
            state_desc = "paused"
        elif state_code == prlsdkapi.prlsdk.consts.VMS_SUSPENDED:
            state_desc = "suspended"
        
        log.debug("Exiting getVMStatus()...")
        return state_desc
        
    def getVMOSInfo(self, vm):
        """
        This method will determine the OS that the VM is running. If it can't
        determine the OS or its version, a generic prlsdkapi.prlsdk.consts
        constant is returned.
        
        @param <b><Object></b>: prlsdapi vm object
        @return <b><Dictionary></b>: Dictionary with OS type & OS version.
        """
        log.debug("Entering getVMOSInfo()...")
        vm_config = vm.get_config()
        # initialize our defaults
        osType = ""
        osVersion = ""
        
        # Obtain the guest OS type and version.
        # OS types are defined as PVS_GUEST_TYPE_xxx constants.
        # For the complete list, see the documentation for
        # the prlsdkapi.prlsdk.consts module or
        # the Parallels Python API Reference guide.
        os_type = vm_config.get_os_type()
        if os_type == prlsdkapi.prlsdk.consts.PVS_GUEST_TYPE_WINDOWS:
            osType = "Windows"
        elif os_type == prlsdkapi.prlsdk.consts.PVS_GUEST_TYPE_LINUX:
            osType = "Linux"
        elif os_type == prlsdkapi.prlsdk.consts.PVS_GUEST_TYPE_MACOS:
            osType = "Mac OS X"
        else:
            osType = "Other type (" + str(os_type) + ")"
    
        # OS versions are defined as PVS_GUEST_VER_xxx constants.
        # Here we assume that MACOS_LAST is Lion since there is no
        # specific const declared for Lions, as of September, 2011
        os_version = vm_config.get_os_version()
        if os_version == prlsdkapi.prlsdk.consts.PVS_GUEST_VER_WIN_XP:
            osVersion = "XP"
        elif os_version == prlsdkapi.prlsdk.consts.PVS_GUEST_VER_WIN_WINDOWS7:
            osVersion = "7"
        elif os_version == prlsdkapi.prlsdk.consts.PVS_GUEST_VER_LIN_UBUNTU:
            osVersion = "Ubuntu"
        elif os_version == prlsdkapi.prlsdk.consts.PVS_GUEST_VER_LIN_FEDORA_5:
            osVersion = "Fedora 5"
        elif os_version == prlsdkapi.prlsdk.consts.PVS_GUEST_VER_MACOS_LAST:
            osVersion = "Lion"
        else:
            osVersion = "Other version (" + str(os_version) + ")"
        
        log.debug("Exiting getVMOSInfo()...")
        return {"osType" : osType, "osVersion" : osVersion}
    
    def getVMNetInfo(self, vm):
        """
        This method will find all the adapters of the Vm & list the MAC address,
        IP (if running) & type of adapter. It uses ARP to determine the ip of
        the adapter.
        
        @param <b><Object></b>: prlsdapi vm object
        @return <b><Dictionary></b>: Dictionary with "type" of adapter, its "mac"
                                     address & assigned "ip" (only when OS is running)
        """
        log.debug("Entering getVMNetInfo()...")
        vm_config = vm.get_config()
        vm_net_adapters = {}
    
        # Obtain the network interface info.
        # The vm.net_adapters sequence contains objects of type VmNetDev.
        count = vm_config.get_net_adapters_count()
        for n in range(count):
            # set the defaulst, just to be sure
            ip = ""
            mac = ""
            emulated_type = ""
            net_adapter = None
            type = ""
            vm_net_adapters[n] = {}
            
            net_adapter = vm_config.get_net_adapter(n)
            emulated_type = net_adapter.get_emulated_type()
    
            if emulated_type == prlsdkapi.prlsdk.consts.PNA_HOST_ONLY:
                type = "host-only"
            elif emulated_type == prlsdkapi.prlsdk.consts.PNA_SHARED:
                type = "shared"
            elif emulated_type == prlsdkapi.prlsdk.consts.PNA_BRIDGED_ETHERNET:
                type = "bridged"
            vm_net_adapters[n]["type"] = type
            
            mac = str(net_adapter.get_mac_address())
            vm_net_adapters[n]["mac"] = mac
            
            # net_adapter.get_net_addresses() is supposed to provide us with
            # the ip of the vm, but I couldn't get it to work with Lion. So
            # this is the next best solution - using arp to figure out the
            # ip. Also this is tailored only to work on OS X. BTW, we check this
            # only if the vm status is running.
            #
            # Find the ip address from arp cache
            # arp -a | grep mac_Address
            if (self.getVMStatus(vm) == 'running'):
                # Mac address format on OS X as used by arp is a little different.
                # The tuples drop the leading 0. So we modify the string that we get
                # the API to match the format of arp.
                arp_mac = [mac[i:i+2] for i in range(0,len(mac),2)]
                arp_mac = ':'.join([re.sub(r'0(\d)',r'\1',i) for i in arp_mac]).lower()
                p1 = subprocess.Popen(["arp", "-a"], stdout=subprocess.PIPE)
                p2 = subprocess.Popen(["grep", arp_mac], stdin=p1.stdout, stdout=subprocess.PIPE)
                p1.stdout.close()
                output = p2.communicate()[0]
                m = re.match(r'^.*?\((.*?)\).*', output)
                ip = m.group(1)
            
            vm_net_adapters[n]["ip"] = ip
            
        log.debug("Exiting getVMNetInfo()...")
        return vm_net_adapters
    
    def startVM(self, vm):
        """
        Starts a VM if it is not in "running" state.
        
        @param <b><Object></b>: prlsdapi vm object
        @return <b><String></b>: "started" if successfully started, otherwise
                                 status as returned by getVMStatus().
        """
        log.debug("Entering startVM()...")
        # Check whether the vm is already running otherwise start it
        status = self.getVMStatus(vm)
        if (status != "running"):
            try:
                vm.start().wait()
                status = 'started'
            except:
                status = "Error: %s" % e
        
        log.debug("Exiting startVM()...")
        return status
    
    def stopVM(self, vm, acpi):
        """
        Stops a VM if it is in "running" state.
        
        @param <b><Object></b>: prlsdapi vm object
        @param <b><Boolean></b>: Whether to perform a graceful shutdown of VM's
                                 OS using ACPI (if the OS supports it).
        @return <b><String></b>: "stopped" if successfully stopped, otherwise
                                 status as returned by getVMStatus().
        """
        log.debug("Entering stopVM()...")
        status = self.getVMStatus(vm)
        if (status == "running"):
            if (acpi):
                try:
                    vm.stop(True).wait()
                    status = 'stopped'
                except:
                    status = "Error: %s" % e
            else:
                try:
                    vm.stop().wait()
                    status = 'stopped'
                except:
                    status = "Error: %s" % e
                    
        log.debug("Exiting stopVM()...")
        return status

class ServerUtils:
    """ A general utility class providing helper methods """
    
    def screenshot(self):
        """
        This method will take a screenshot of main monitor & return it if
        successful or it'll return an empty string

        @return <b><Binary></b>: Returns a jpg, if one was generated
        """
        log.debug("Entering screenshot()...")
        screen = '/tmp/screen.jpg'
        image = None

        try:
            os.system('screencapture -m %s' % screen)
            image = open(screen, 'rt').read()
            log.debug("Generated screenshot")
        except:
            log.exception("Could not generate screen")
        finally:
            os.remove(screen)
        
        log.debug("Exiting screenshot()...")
        return image

    def parseJSONFromPOST(self):
        """
        This method will parse the JSON input from the POST body & return a
        python dict object

        @return <b>parsed JSON object</b>:  Could either be a python dictionary
                                            or an array (depends on JSON sent)
        """

        log.debug("Entered parseJSONFromPOST()...")
        try:
            data = json.loads(request.body.readline())
            log.debug(data)
            log.debug("Exiting parseJSONFromPOST()...")
            return data
        except ValueError:
            log.error("Bad request: Exiting parseJSONFromPOST()...")
            abort(400, 'Bad request: Could not decode request body,\
                                    JSON expected.')

    def osDetails(self):
        """
        This method will return the OS details on which the server is running

        @return <b><Dictionary></b>:
                Returns 'osname' : Name of the OS
                        'osbit'  : 32 or 64 bit OS
                        'osver'  : version of the OS if available
        """
        log.debug("Entering osDetails()...")
        details = {}
        cmd = 'sw_vers -productName'
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            details['osname'] = p.stdout.read().rstrip('\n')
        except:
            e = sys.exc_info()[1]
            log.error(e)

        cmd = 'sw_vers -productVersion'
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            details['osver'] = p.stdout.read().rstrip('\n')
        except:
            e = sys.exc_info()[1]
            log.error(e)

        cmd = 'uname -a | grep RELEASE_I386'
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            if (p.stdout.read()):
                details['osbit'] = 32
            else:
                details['osbit'] = 64
        except:
            e = sys.exc_info()[1]
            log.error(e)
        
        log.debug("Exiting osDetails()...")
        return details

################################################################################

vmServer = Bottle()
vmManager = PrlVMManager()

################################################################################
# Routes
################################################################################
@vmServer.error(404)
def error404(error):
    return 'Ooh, over there. Something shiny!'

@vmServer.get('/routes')
def routes():
    """
    Returns list of routes available

    Resource : <b>/routes</b>
    """
    routes = ""
    for route in vmServer.routes:
        routes += route['rule']
    return routes

@vmServer.get('/screenshot')
def screenshot():
    """
    This method will take a screenshot of the main monitor & return
    base64 encoded image back.

    Resource : <b>/screenshot</b>

    @return <b><JSONResponseObject></b>
    """
    status = None
    value = None
    screen = None

    utils = serverUtils()
    image = utils.screenshot()
    if (image):
        status = 0
        value = "Generated screenshot"
        screen = base64.b64encode(image)
    else:
        status = 9
        value = "Could not generate screenshot, check logs"

    response.content_type = 'application/json; charset=utf-8'
    ret = {'status':status, 'value':value, 'screen':screen}
    return ret

@vmServer.get('/os')
def os():
    """
    This method will return the OS details vmManager is running on

    Resource : <b>/os</b>

    @return <b><JSONResponseObject></b>
    """
    status = None
    value = None
    screen = None

    utils = serverUtils()
    details = utils.osDetails()
    if (details):
        status = 0
        value = details
    else:
        status = 9
        value = "Could not generate screenshot, check logs"

    response.content_type = 'application/json; charset=utf-8'
    ret = {'status':status, 'value':value, 'screen':screen}
    return ret

@vmServer.get('/VM/list')
def vmList():
    """
    Returns list of VMs on the local machine.

    Resource : <b>/VM/list</b>

    @return <b><JSONResponseObject></b>
    """
    log.debug("Entered vmList()...")

    value = None
    status = None
    list = vmManager.getVMList()
    log.debug(list)
    if (list):
        value = list
        status = 0
    else:
        status = 9
        value = "Could not get list of VMs."

    log.debug("Exiting vmList()...")
    response.content_type = 'application/json; charset=utf-8'
    return {'status':status, 'value':value}

@vmServer.get('/VM/listWithInfo')
def vmListWithInfo():
    """
    Returns list of VMs on the local machine and their information

    Resource : <b>/VM/listAllWithInfo</b>

    @return <b><JSONResponseObject></b>
    """
    log.debug("Entered vmListAllWithInfo()...")

    value = None
    status = None
    list = vmManager.getVMListWithInfo()
    log.debug(list)
    if (list):
        value = list
        status = 0
    else:
        status = 9
        value = "Could not get list of VMs."

    log.debug("Exiting vmList()...")
    response.content_type = 'application/json; charset=utf-8'
    return {'status':status, 'value':value}

@vmServer.get('/VM/:vmName/info')
def vmInfo(vmName):
    """
    Returns information about the VM such as os, network, status etc

    Resource : <b>/VM/:vmName/info</b>

    @return <b><JSONResponseObject></b>
    """
    log.debug("Entered vmInfo()...")
    
    vm = vmManager.searchVM(vmName)
    value = None
    status = None 
    if (vm):
        value = vmManager.getVMInfo(vm)
        status = 0
    else:
        value = 'Could not find the given VM name'
        status = 9
    
    log.debug("Exiting vmInfo()...")
    response.content_type = 'application/json; charset=utf-8'
    return {'status' : status, 'value' : value}

@vmServer.get('/VM/:vmName/status')
def vmStatus(vmName):
    """
    Returns status of the VM

    Resource : <b>/VM/:vmName/status</b>

    @return <b><JSONResponseObject></b>
    """
    log.debug("Entered vmStatus()...")
    
    vm = vmManager.searchVM(vmName)
    value = None
    status = None 
    if (vm):
        value = vmManager.getVMStatus(vm)
        status = 0
    else:
        value = 'Could not find the given VM name'
        status = 9
    
    log.debug("Exiting vmStatus()...")
    response.content_type = 'application/json; charset=utf-8'
    return {'status' : status, 'value' : value}

@vmServer.get('/VM/:vmName/os')
def vmOSInfo(vmName):
    """
    Returns OS that VM is running

    Resource : <b>/VM/:vmName/os</b>

    @return <b><JSONResponseObject></b>
    """
    log.debug("Entered vmOSInfo()...")
    
    vm = vmManager.searchVM(vmName)
    value = None
    status = None 
    if (vm):
        value = vmManager.getVMOSInfo(vm)
        status = 0
    else:
        value = 'Could not find the given VM name'
        status = 9
    
    log.debug("Exiting vmOSInfo()...")
    response.content_type = 'application/json; charset=utf-8'
    return {'status' : status, 'value' : value}

@vmServer.get('/VM/:vmName/adapters')
def vmAdapterInfo(vmName):
    """
    Returns the adapter(s) details of the VM

    Resource : <b>/VM/:vmName/adapters</b>

    @return <b><JSONResponseObject></b>
    """
    log.debug("Entered vmAdapterInfo()...")
    
    vm = vmManager.searchVM(vmName)
    value = None
    status = None 
    if (vm):
        value = vmManager.getVMNetInfo(vm)
        status = 0
    else:
        value = 'Could not find the given VM name'
        status = 9
    
    log.debug("Exiting vmAdapterInfo()...")
    response.content_type = 'application/json; charset=utf-8'
    return {'status' : status, 'value' : value}

@vmServer.get('/VM/:vmName/start')
def vmStart(vmName):
    """
    Start the VM if it is not already running. This just refers to the VM &
    not the OS running (or stopped) in it.

    Resource : <b>/VM/:vmName/start</b>

    @return <b><JSONResponseObject></b>
    """
    log.debug("Entered vmStart()...")
    
    vm = vmManager.searchVM(vmName)
    value = None
    status = None 
    if (vm):
        value = vmManager.startVM(vm)
        status = 0
    else:
        value = 'Could not find the given VM name'
        status = 9
    
    log.debug("Exiting vmStart()...")
    response.content_type = 'application/json; charset=utf-8'
    return {'status' : status, 'value' : value}

@vmServer.put('/VM/:vmName/stop')
def vmStop(vmName):
    """
    Stop the VM if it is running. This can also stop the OS.

    Resource : <b>/VM/:vmName/start</b>
    POST Data: JSON object with key 'acpi' as true or false value.
    
    @code curl -d"{\"acpi\":true}" -X PUT http://localhost:9898/VM/Lion123/stop
    
    @return <b><JSONResponseObject></b>
    """
    log.debug("Entered vmStart()...")
    
    b_acpi = False
    utils = ServerUtils()
    if (request.body.readline()):
        data = utils.parseJSONFromPOST()
        if data.has_key('acpi'):
            b_acpi = data["acpi"]

    vm = vmManager.searchVM(vmName)
    value = None
    status = None 
    if (vm):
        value = vmManager.stopVM(vm, b_acpi)
        status = 0
    else:
        value = 'Could not find the given VM name'
        status = 9
    
    log.debug("Exiting vmStart()...")
    response.content_type = 'application/json; charset=utf-8'
    return {'status' : status, 'value' : value}

run(app=vmServer, host='0.0.0.0', port=9898, reloader=reload)
