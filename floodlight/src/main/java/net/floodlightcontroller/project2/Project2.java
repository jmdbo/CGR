package net.floodlightcontroller.project2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.MacVlanPair;
import net.floodlightcontroller.learningswitch.LearningSwitch;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.util.OFMessageUtils;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFErrorMsg;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.util.HexString;
import org.projectfloodlight.openflow.util.LRULinkedHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Project2  implements IFloodlightModule, IOFMessageListener {

    // Module dependencies
    protected IFloodlightProviderService floodlightProvider;
    protected static Logger log;
   
    // CGR: data structures for the learning switch feature
    // Stores the learned state for each switch
    protected Map<IOFSwitch, Map<MacAddress, OFPort>> macToSwitchPortMap;
	protected HashMap<Long, Long> blacklist;
   
 // flow-mod - for use in the cookie
     public static final int PROJECT2_APP_ID = 1;
     // LOOK! This should probably go in some class that encapsulates
     // the app cookie management
     public static final int APP_ID_BITS = 12;
     public static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
     public static final long PROJECT2_COOKIE = (long) (PROJECT2_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;
    
    // for managing our map sizes
    protected static final int MAX_MACS_PER_SWITCH  = 1000;
   
    @Override
    public String getName() {
         return Project2.class.getSimpleName();
    }
   
    //////CGR utility methods to store/retrive  MACAddress/Port Mappings in the macToSwitchPortMap
   
    /**
     * Adds a host to the MAC->SwitchPort mapping
     * @param sw The switch to add the mapping to
     * @param mac The MAC address of the host to add
     * @param vlan The VLAN that the host is on
     * @param portVal The switchport that the host is on
     */
    protected void addToPortMap(IOFSwitch sw, MacAddress mac, OFPort portVal) {
       
        Map<MacAddress, OFPort> swMap = macToSwitchPortMap.get(sw);

        if (swMap == null) {
            // To make it possible to be accessible by a REST API we need to make it thread safe
            swMap = Collections.synchronizedMap(new LRULinkedHashMap<MacAddress, OFPort>(MAX_MACS_PER_SWITCH)); // creates HashMap for mac/port
            macToSwitchPortMap.put(sw, swMap); // stores the  HashMap for mac/por for the key values of the specified switch
        }
        swMap.put(mac, portVal); //stores mac and port in the mac/port HashMap
    }

    /**
     * Removes a host from the MAC->SwitchPort mapping
     * @param sw The switch to remove the mapping from
     * @param mac The MAC address of the host to remove
     * @param vlan The VLAN that the host is on
     */
    protected void removeFromPortMap(IOFSwitch sw, MacAddress mac) {
   
        Map<MacAddress, OFPort> swMap = macToSwitchPortMap.get(sw);
        if (swMap != null) {
            swMap.remove(mac);
        }
    }

    /**
     * Get the port that a MAC is associated with
     * @param sw The switch to get the mapping from
     * @param mac The MAC address to get
     * @param vlan The VLAN number to get
     * @return The port the host is on
     */
    public OFPort getFromPortMap(IOFSwitch sw, MacAddress mac ) {

        Map<MacAddress, OFPort> swMap = macToSwitchPortMap.get(sw);
        if (swMap != null) {
            return swMap.get(mac);
        }

        // if none found
        return null;
    }

    /**
     * Clears the MAC -> SwitchPort map for all switches
     */
    public void clearLearnedTable() {
        macToSwitchPortMap.clear();
    }

    /**
     * Clears the MAC -> SwitchPort map for a single switch
     * @param sw The switch to clear the mapping for
     */
    public void clearLearnedTable(IOFSwitch sw) {
        Map<MacAddress, OFPort> swMap = macToSwitchPortMap.get(sw);
        if (swMap != null) {
            swMap.clear();
        }
    }

   
   

     /**
     * Writes an OFPacketOut message to a switch.
     * @param sw The switch to write the PacketOut to.
     * @param packetInMessage The corresponding PacketIn.
     * @param egressPort The switchport to output the PacketOut.
     */
    private void writePacketOutForPacketIn(IOFSwitch sw,
                                          OFPacketIn packetInMessage,
                                          OFPort egressPort) {
       
        OFMessageUtils.writePacketOutForPacketIn(sw, packetInMessage, egressPort);
    }
   
    /**
     * Writes a OFFlowMod to a switch with the specified match and actions.
     * @param sw The switch tow rite the flowmod to.
     * @param command The FlowMod actions (add, delete, etc).
     * @param bufferId The buffer ID if the switch has buffered the packet.
     * @param match The OFMatch structure to write.
     * @param al The actions list for the Flow entry
     * @param IdleTimeout the idle timeout in seconds
     * @param HardTimeout the hard timeout in seconds
     */
    private void writeFlowMod(IOFSwitch sw, OFFlowModCommand command, OFBufferId bufferId,
            Match match, List<OFAction> al,  OFPort outPort, short IdleTimeout, short HardTimeout) {
        // from openflow 1.0 spec - need to set these on a struct ofp_flow_mod:
        // struct ofp_flow_mod {
        //    struct ofp_header header;
        //    struct ofp_match match; /* Fields to match */
        //    uint64_t cookie; /* Opaque controller-issued identifier. */
        //
        //    /* Flow actions. */
        //    uint16_t command; /* One of OFPFC_*. */
        //    uint16_t idle_timeout; /* Idle time before discarding (seconds). */
        //    uint16_t hard_timeout; /* Max time before discarding (seconds). */
        //    uint16_t priority; /* Priority level of flow entry. */
        //    uint32_t buffer_id; /* Buffered packet to apply to (or -1).
        //                           Not meaningful for OFPFC_DELETE*. */
        //    uint16_t out_port; /* For OFPFC_DELETE* commands, require
        //                          matching entries to include this as an
        //                          output port. A value of OFPP_NONE
        //                          indicates no restriction. */
        //    uint16_t flags; /* One of OFPFF_*. */
        //    struct ofp_action_header actions[0]; /* The action length is inferred
        //                                            from the length field in the
        //                                            header. */
        //    };
       
        OFFlowMod.Builder fmb;
        if (command == OFFlowModCommand.DELETE) {           //build
            fmb = sw.getOFFactory().buildFlowDelete();
        } else {
            fmb = sw.getOFFactory().buildFlowAdd();
        }
        fmb.setMatch(match); // set the match
        fmb.setCookie((U64.of(Project2.PROJECT2_COOKIE))); //cookie to identify that the flow was set by this application
        fmb.setIdleTimeout(IdleTimeout); // set the timeouts
        fmb.setHardTimeout(HardTimeout);
        fmb.setPriority(100); // set priority
        fmb.setBufferId(bufferId);
        fmb.setOutPort((command == OFFlowModCommand.DELETE) ? OFPort.ANY : outPort);
        Set<OFFlowModFlags> sfmf = new HashSet<OFFlowModFlags>();
        if (command != OFFlowModCommand.DELETE) {
            sfmf.add(OFFlowModFlags.SEND_FLOW_REM);
        }
        fmb.setFlags(sfmf);
       
        fmb.setActions(al);

       
        log.info("{} {} flow mod {}",
                    new Object[]{ sw, (command == OFFlowModCommand.DELETE) ? "deleting" : "adding", fmb.build() });
   

        // build flowMod and write it out
          sw.write(fmb.build());
       
    }
   
   
   
    /**
     * Processes a OFPacketIn message. If the switch has learned the MAC to port mapping
     * for the pair it will write a FlowMod for it and install it in the switch. If the mapping has not been learned it
     * we will flood the packet.
     * @param sw
     * @param pi
     * @param cntx
     * @return
     */
    private Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {

        //get Packet_In data into Ethernet Packet
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        //get MAC addresses from the Packet_in data
        MacAddress sourceMac = eth.getSourceMACAddress();
        MacAddress destMac = eth.getDestinationMACAddress();
       
        if (sourceMac == null) {
            sourceMac = MacAddress.NONE;
        }
        if (destMac == null) {
            destMac = MacAddress.NONE;
        }

/* CGR: Do work here to learn the port for this MAC
        ....
*/
        //Verify if MAC is a Unicast address
        if(sw!=null && (sourceMac.getLong() & 0x010000000000L) == 0){
        	addToPortMap(sw, sourceMac, pi.getInPort());
        }
/* CGR: Do work here to implement super firewall
        Hint: You may check connection limitation here.
        ....
*/

/* CGR: Filter-out hosts in blacklist
 *         Also, when the host is in blacklist check if the blockout time is
 *         expired and handle properly
 */
        
        if (blacklist.containsKey(sourceMac.getLong())){
        	long blockout = blacklist.get(sourceMac.getLong());
        	Date d = new Date();
        	if(blockout >= d.getTime())
        		return Command.CONTINUE;
        }
        
        if (blacklist.containsKey(destMac.getLong())){
        	long blockout = blacklist.get(destMac.getLong());
        	Date d = new Date();
        	if(blockout >= d.getTime())
        		return Command.CONTINUE;
        }
          
            


/* CGR: Ask the switch to flood the packet to all of its ports
 *         Thus, this module currently works as a dummy hub
 *         After changing it to a learning switch comment the following line out
 */
        //this.writePacketOutForPacketIn(sw, pi, OFPort.FLOOD);
        /*log.info("floding packet in:"
                + " switch {} Src MAC {} dest MAC {}",
                new Object[]{ sw, sourceMac.toString(), destMac.toString() });*/

// CGR: Now output flow-mod and/or packet
        // CGR: Fill out the following ???? to obtain outPort from a structure where you store the learned macs
        OFPort outPort = getFromPortMap(sw, destMac);
        if (outPort == null) {
            // CGR If we haven't learned the port for the dest MAC, flood it
            this.writePacketOutForPacketIn(sw, pi, OFPort.FLOOD);
        } else if (outPort.equals(pi.getInPort())) {
            log.info("ignoring packet that arrived on same port as learned destination:"
                    + " switch {} vlan {} dest MAC {} port {}",
                    new Object[]{ sw, eth.getVlanID(), destMac.toString(), outPort.getPortNumber() });
        } else {
            // Send the buffered PacketIn in a PacketOut and add flow table entry matching source MAC, dest MAC and input port
            // that sends to the port we previously learned for the dest MAC
           
            OFPort inPort = pi.getInPort(); // get in port
           
            OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut(); // create packet out
            // set actions for the PacketOut
            List<OFAction> actions = new ArrayList<OFAction>();
            actions.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffFFffFF).build()); //create action to forward to learned port (variable ouPort)
            pob.setActions(actions); // set the actions
            pob.setBufferId(pi.getBufferId()); // set buffer id same as PacketIn
               pob.setInPort(inPort); //set the in port of the PacketOut same as the one in PacketIn
               sw.write(pob.build()); // build the PacketOUt and send it to the switch
              
               //create the match to match on source MAC, dest MAC and input port to build a flow mod  that sends to the port we previously learned for the dest MAC.
                
               Match.Builder mb = sw.getOFFactory().buildMatch();
            mb.setExact(MatchField.IN_PORT, inPort)   //in port of the Packet_In
            .setExact(MatchField.ETH_SRC, sourceMac)  //src address of the Packet_In
            .setExact(MatchField.ETH_DST, destMac);  // dest address of the Packet_In
            Match match = mb.build();
              
               //create the list of actions for the packet to be forwarded to the learned outPort
            
            List<OFAction> al = new ArrayList<OFAction>(); //create action list
            al.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(0xffFFffFF).build()); // buid action forward in por outPort
            //finally build the flow with this match and actions ans write it to the switch
            this.writeFlowMod(sw, OFFlowModCommand.ADD, pi.getBufferId(), match, al, outPort, (short)0, (short)0);
        }
        
        return Command.CONTINUE;
    }   
   
   
    /**
     * Processes a flow removed message. We will delete the learned MAC/VLAN mapping from
     * the switch's table.
     * @param sw The switch that sent the flow removed message.
     * @param flowRemovedMessage The flow removed message.
     * @return Whether to continue processing this message or stop.
     */
/*    private Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved flowRemovedMessage) {
        if (!flowRemovedMessage.getCookie().equals(U64.of(Project2.PROJECT2_COOKIE))) {
            return Command.CONTINUE;
        }
       
        log.info("{} flow entry removed {}", sw, flowRemovedMessage);
       
        Match match = flowRemovedMessage.getMatch();
        //we can get the  Mac addresses from the Match in the removed flow.
        MacAddress sourceMac = match.get(MatchField.ETH_SRC);
        MacAddress destMac =  match.get(MatchField.ETH_SRC); 
        // When a flow entry expires, it means the device with the matching source
        // MAC address either stopped sending packets or moved to a different
        // port.  If the device moved, we can't know where it went until it sends
        // another packet, allowing us to re-learn its port.  Meanwhile we remove
        // it from the macVlanToPortMap to revert to flooding  packets to this device.
        return Command.CONTINUE;
    }
*/   

    //OF message listener
    @Override
    public net.floodlightcontroller.core.IListener.Command receive(
            IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
        case PACKET_IN:
            return this.processPacketInMessage(sw, (OFPacketIn) msg, cntx);
        /*
        case FLOW_REMOVED:
            return this.processFlowRemovedMessage(sw, (OFFlowRemoved) msg);
        */
        case ERROR:
            log.error("received an error {} from switch {}", (OFErrorMsg) msg, sw);
            return Command.CONTINUE;
        default:
            break;
    }
    log.error("received an unexpected message {} from switch {}", msg, sw);
        return Command.CONTINUE; // allow the message to be handled by other PACKET_IN handlers as well (other floodlight controller modules.
    }
   
    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        // TODO Auto-generated method stub
        return null;
    }

    /* Tell the module loader we depend on it by modifying the getModuleDependencies() function.
     * */
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
            l.add(IFloodlightProviderService.class);
            return l;
    }

    @Override
    public void init(FloodlightModuleContext context)
            throws FloodlightModuleException {
         floodlightProvider =
                    context.getServiceImpl(IFloodlightProviderService.class); //get controller instance
         log = LoggerFactory.getLogger(Project2.class); //create logger class
    // CGR: Initialize data structures
            macToSwitchPortMap =
                    new ConcurrentHashMap<IOFSwitch, Map<MacAddress, OFPort>>();
            blacklist =
                    new HashMap<Long, Long>();
           
            log.info("Project 2 modules initialized");
       
    }
    
    @Override
    public void startUp(FloodlightModuleContext context)
            throws FloodlightModuleException {
             floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this); // register to receive Packet_In messages
            //floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this); //register to receive Flow removed OF messages
            floodlightProvider.addOFMessageListener(OFType.ERROR, this); //register to receive error OF messages
       
    }

}