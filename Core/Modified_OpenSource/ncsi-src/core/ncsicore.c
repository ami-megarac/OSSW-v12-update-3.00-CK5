/*
 ****************************************************************
 **                                                            **
 **    (C)Copyright 2009-2015, American Megatrends Inc.        **
 **                                                            **
 **            All Rights Reserved.                            **
 **                                                            **
 **        5555 Oakbrook Pkwy Suite 200, Norcross,             **
 **                                                            **
 **        Georgia - 30093, USA. Phone-(770)-246-8600.         **
 **                                                            **
 ****************************************************************
 */
/****************************************************************

  Author	: Samvinesh Christopher

  Module	: NCSI Detect and Enable Modules
			
  Revision	: 1.0  

  Changelog : 1.0 - Initial Version [SC]

*****************************************************************/
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/version.h>

#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <asm/byteorder.h>
#include <linux/delay.h>
#include "ncsi.h"
#include "interfaces.h"

extern int UserAuto;
extern int UserPackageID;
extern int UserChannelID;
extern int UserSpeed;
extern int UserDuplex;
extern int UserAutoNeg;
extern int UserVetoBit;
extern int InitComplete;
extern int verbose;
extern int UserVlanID;
#ifdef CONFIG_SPX_FEATURE_NCSI_RESET_INTERFACE_IN_USER_SETTINGS
extern int UserInitEnabled;
#endif
extern unsigned int UserCommand[NCSI_COMMAND_SIZE];
extern int EnableSetLink;

extern char UserInterface[];
extern struct workqueue_struct *ncsi_wq;
void NSCI_Detect_Package_Channel (NCSI_IF_INFO *info, UINT8 PackageID, UINT8 ChannelID);
int NCSI_Enable_Info(NCSI_IF_INFO *info);
UINT8 ChannelCount[MAX_PACKAGE_ID] = {MAX_CHANNEL_ID};
void NCSI_Configure_Channel (NCSI_IF_INFO *info, UINT8 PackageID, UINT8 ChannelID);

#ifdef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES
int multi_pkg_polling = 1;
UINT8 CurrentPkgID, CurrentChID;
#endif

int ValidPackages = 0;
int all_ch_link_down = 1;
int linkup_index_pre = 0;
int is_async_reset = 0; 

extern struct timer_list switchTimer;  /* A Kernel Timer to periodically issue GetLinkStatus Command */
extern int isSwitchTimerInitialized;

#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS) ||\
	defined (CONFIG_SPX_FEATURE_POLL_FOR_ASYNC_RESET)
extern int verbose;

extern struct timer_list getLinkStatusTimer;  /* A Kernel Timer to periodically issue GetLinkStatus Command */
extern int isPollTimerInitialized;

#ifdef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES
static void
NCSI_MultiPackageCheckStatus(struct work_struct *data)
{
	int retval = 0;
	GetLinkStatusReq_T *work;
	NCSI_IF_INFO *info;
	UINT32 linkstate = 0;
	UINT8 PackageID;
	UINT8 ChannelID;
	int i = 0; 
#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS)
    int link_changed = 1, linkup_index = 0;
#endif
    
    if(data == NULL)
        return;

    work = (GetLinkStatusReq_T *) data;
    info = GetInterfaceInfoByName(work->InterfaceName);

    if(info != NULL)
    {
        netif_carrier_on(info->dev);    //make sure we can transmit
        
        if (info->AutoSelect) // Auto Failover mode
        {
        	if (multi_pkg_polling == 1)
        	{
        		for(i=0;i<info->TotalChannels;i++)
        		{
        			if (info->ChannelInfo[i].Valid == 0) {
        				continue;
        			}
        			PackageID = info->ChannelInfo[i].PackageID;
        			ChannelID = info->ChannelInfo[i].ChannelID;
			
        			retval = NCSI_Issue_GetLinkStatus(info, PackageID, ChannelID, &linkstate );
        			if (linkstate & LINK_STATUS_UP)
        			{
#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS)
        				linkup_index = linkup_index | (0x01 << i);
#endif
        				CurrentPkgID = PackageID;
        				CurrentChID = ChannelID;
        				multi_pkg_polling = 0;
        			}
        		
        			if ( retval == NCSI_INIT_REQUIRED ) {
        				break;
        			}
        		}
        	}
        	else
        	{
        		PackageID = CurrentPkgID;
        		ChannelID = CurrentChID;
        		retval = NCSI_Issue_GetLinkStatus(info, PackageID, ChannelID, &linkstate );
        		if (linkstate & LINK_STATUS_UP)
        		{
#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS)
        			linkup_index = linkup_index | (0x01 << i);
#endif
        		}
        		else
        		{
        			multi_pkg_polling = 1;
        		}
        	}
        }
        else
        {
        	PackageID = info->ForcePackage;
        	ChannelID = info->ForceChannel;
        	retval = NCSI_Issue_GetLinkStatus(info, PackageID, ChannelID, &linkstate );
        	if (linkstate & LINK_STATUS_UP)
        	{
#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS)
        		linkup_index = linkup_index | (0x01 << i);
#endif
        	}
        	else
        	{
        		multi_pkg_polling = 1;
        	}
        }
	}

		
#if defined(CONFIG_SPX_FEATURE_POLL_FOR_ASYNC_RESET)
	// If the controller reverts back to initial state after an asynchronous reset
	// Re configure the link

	if ( NCSI_INIT_REQUIRED == retval )
	{
		while (InitComplete == 0)
		{
			if(verbose & SHOW_MESSAGES)
			{
				printk ("NCSI : Initialization in progress, please wait...\n");
			}
			msleep(1000);
		}
		InitComplete = 0;
		is_async_reset = 1;
					
		printk(KERN_WARNING"Asynchronous Reset Detected !!!\n");			
		printk (KERN_WARNING"NCSI(%s):(%d.%d) Reset for NCSI Interface..\n",
				work->InterfaceName, work->PackageId, work->ChannelId);

		/* Detect and Configure the NC-SI Interface that 
         * previous detected */
        netif_carrier_on(info->dev);
        for(i=0;i<info->TotalChannels;i++)
        {
        	if (info->ChannelInfo[i].Valid == 0)
        		continue;
	        PackageID = info->ChannelInfo[i].PackageID;
	        ChannelID = info->ChannelInfo[i].ChannelID;
			NCSI_Configure_Channel(info, PackageID, ChannelID);
        }

        // Enabling previously active channel
		NCSI_Enable_Info(info);
		InitComplete = 1;
		is_async_reset = 0;

	#if 0
			#ifdef CONFIG_SPX_FEATURE_NCSI_FORCE_LAN_SPEED_10G
		NCSI_Issue_SetLink(info,(UINT8)PackageID,(UINT8)ChannelID,0/*Force Speed*/,LINK_ENABLE_10_GBPS,LINK_ENABLE_FULL_DUPLEX) ;
			#else
		// Setting Auto Negotiate for link speed
		NCSI_Issue_SetLink(info,(UINT8)work->PackageId,(UINT8)work->ChannelId,1,0,0);
			#endif
	#endif		
    }
	else
	{
#endif

	/* Update the 'linkstate' value got via CMD_GET_LINK_STATUS for updating the ethtool structure
	 * as we need this update to show proper interface information via 'ethtool <interface>' command
	 * as well as this link state will be queried by the bond driver from linux kernel while enabling
	 * the bond, if this update is not done then while enabling bond using the NCSI interface as the
	 * active slave will automatically discard the interface as the link state will be by default
	 * reported as DOWN which will make the bond to pick other physical interface which is in UP state
	 *
	 * We might also get AEN packets from other channels which can conflict with the netmon driver and
	 * report NETDEV_CHANGE event continuously so to prevent that updating the ethinfo only when the 
	 * link state is UP */
	if (linkstate & LINK_STATUS_UP)
	{
		GetEthtoolInfoFromLink (info,linkstate);
	}

#if defined(CONFIG_SPX_FEATURE_POLL_FOR_ASYNC_RESET)
	}
#endif

#ifdef CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS
	// If AEN is not enabled in the interface, alert netdevice notifiers
	// DisplayLinkStatus will make link down/up event and cause network short disconnect.
	if ( !info->AENEnabled && NCSI_ERR_SUCCESS == retval )	
	{
		if(linkup_index_pre != linkup_index){
			//Check enabled port still link up
			for(i=0;i<info->TotalChannels;i++)
			{								
				if(!info->AutoSelect){
					//Manual switch
					if(info->ChannelInfo[i].Enabled == 1){
						if(((linkup_index >> i) & 0x01) == ((linkup_index_pre >> i) & 0x01))
							link_changed = 0;
					}
				}else{
					//Auto failover
					if((info->ChannelInfo[i].Enabled == 1) && ((linkup_index >> i) & 0x01))				
						link_changed = 0;					
				}
			}
		}else
			link_changed = 0;
			
		if(link_changed){
			if(verbose & (SHOW_LINK_INFO | SHOW_MESSAGES))
				printk("NCSI(%s): Detected channel changed, Packages %d, linkup_index %d\n",info->dev->name, PackageID, linkup_index);
			DisplayLinkStatus(info, linkstate, 0);
		}
		linkup_index_pre = linkup_index;
	}
		
#endif
    
    kfree( (void *)data );
    return;
}
#endif

/*
 * @Brief : Checks the current link state, if async reset has occurred reconfigures the channel
 *          if AENs are not enabled, alerts all netdevice notifiers
 */
#ifndef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES
static void
NCSI_CheckStatusAndResetNCSI(struct work_struct *data)
{
    int retval = 0;
    GetLinkStatusReq_T *work;
    NCSI_IF_INFO *info;
    UINT32 linkstate = 0;
    UINT8 PackageID=0;
    UINT8 ChannelID=0;
    int i = 0; 
#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS)
    int link_changed = 1, linkup_index = 0;
#endif
    
    if(data == NULL)
        return;

    work = (GetLinkStatusReq_T *) data;
    info = GetInterfaceInfoByName(work->InterfaceName);

    if(info != NULL)
    {
        netif_carrier_on(info->dev);    //make sure we can transmit
	for(i=0;i<info->TotalChannels;i++)
	{
		if (info->ChannelInfo[i].Valid == 0) {
			continue;
		}
		PackageID = info->ChannelInfo[i].PackageID;
		ChannelID = info->ChannelInfo[i].ChannelID;
		retval = NCSI_Issue_GetLinkStatus(info, PackageID, ChannelID, &linkstate );
#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS)
		if (linkstate & LINK_STATUS_UP)
			linkup_index = linkup_index | (0x01 << i);
#endif
		if ( retval == NCSI_INIT_REQUIRED) {
			break;
		}
	}

	
#if defined(CONFIG_SPX_FEATURE_POLL_FOR_ASYNC_RESET)
	// If the controller reverts back to initial state after an asynchronous reset
	// Re configure the link

	if ( NCSI_INIT_REQUIRED == retval )
	{
		while (InitComplete == 0)
		{
			if(verbose & SHOW_MESSAGES)
			{
				printk ("NCSI : Initialization in progress, please wait...\n");
			}
			msleep(1000);
		}
		InitComplete = 0;
		is_async_reset = 1;
				
		printk(KERN_WARNING"Asynchronous Reset Detected !!!\n");			
		printk (KERN_WARNING"NCSI(%s):(%d.%d) Reset for NCSI Interface..\n",
				work->InterfaceName, work->PackageId, work->ChannelId);

		/* Detect and Configure the NC-SI Interface that 
                 * previous detected */
                netif_carrier_on(info->dev);
                for(i=0;i<info->TotalChannels;i++)
                {
                        if (info->ChannelInfo[i].Valid == 0)
                                continue;
                        PackageID = info->ChannelInfo[i].PackageID;
                        ChannelID = info->ChannelInfo[i].ChannelID;
			NCSI_Configure_Channel(info, PackageID, ChannelID);
                }

		// Enabling previously active channel
		NCSI_Enable_Info(info);
		InitComplete = 1;
		is_async_reset = 0;

#if 0
		#ifdef CONFIG_SPX_FEATURE_NCSI_FORCE_LAN_SPEED_10G
    			NCSI_Issue_SetLink(info,(UINT8)PackageID,(UINT8)ChannelID,0/*Force Speed*/,LINK_ENABLE_10_GBPS,LINK_ENABLE_FULL_DUPLEX) ;
		#else
			// Setting Auto Negotiate for link speed
			NCSI_Issue_SetLink(info,(UINT8)work->PackageId,(UINT8)work->ChannelId,1,0,0);
		#endif
#endif		
        }
	else
	{
#endif

	/* Update the 'linkstate' value got via CMD_GET_LINK_STATUS for updating the ethtool structure
	 * as we need this update to show proper interface information via 'ethtool <interface>' command
	 * as well as this link state will be queried by the bond driver from linux kernel while enabling
	 * the bond, if this update is not done then while enabling bond using the NCSI interface as the
	 * active slave will automatically discard the interface as the link state will be by default
	 * reported as DOWN which will make the bond to pick other physical interface which is in UP state
	 *
	 * We might also get AEN packets from other channels which can conflict with the netmon driver and
	 * report NETDEV_CHANGE event continuously so to prevent that updating the ethinfo only when the 
	 * link state is UP */
	if (linkstate & LINK_STATUS_UP)
	{
		GetEthtoolInfoFromLink (info,linkstate);
	}

#if defined(CONFIG_SPX_FEATURE_POLL_FOR_ASYNC_RESET)
	}
#endif

#ifdef CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS
	// If AEN is not enabled in the interface, alert netdevice notifiers
	// DisplayLinkStatus will make link down/up event and cause network short disconnect.
	if ( !info->AENEnabled && NCSI_ERR_SUCCESS == retval )	
	{		
		if(linkup_index_pre != linkup_index){
			//Check enabled port still link up
			for(i=0;i<info->TotalChannels;i++)
			{								
				if(!info->AutoSelect){
					//Manual switch
					if(info->ChannelInfo[i].Enabled == 1){
						if(((linkup_index >> i) & 0x01) == ((linkup_index_pre >> i) & 0x01))
							link_changed = 0;
					}
				}else{
					//Auto failover
					if((info->ChannelInfo[i].Enabled == 1) && ((linkup_index >> i) & 0x01))				
						link_changed = 0;					
				}
			}
		}else
			link_changed = 0;
		
		if(link_changed){
			if(verbose & (SHOW_LINK_INFO | SHOW_MESSAGES))
				printk("NCSI(%s): Detected channel changed, Packages %d, linkup_index %d\n",info->dev->name, PackageID, linkup_index);
			DisplayLinkStatus(info, linkstate, 0);
		}
		linkup_index_pre = linkup_index;
	}
	
#endif
    }

    kfree((void *)data);
    return;
}
#endif

/* 
 * @ Brief: Create a job on the workqueue for each configured NC-SI interface,
 *          in order to check the link state
 */
static
void CheckLinkStatus ( NCSI_IF_INFO *info )
{
	GetLinkStatusReq_T *work = NULL;

	if(netif_running(info->dev))
	{
		if ( info->EnabledChannelID != -1 && info->EnabledPackageID != -1 && InitComplete == 1)
		{
			work = (GetLinkStatusReq_T *) kmalloc(sizeof(GetLinkStatusReq_T), GFP_ATOMIC);

		        if(work == NULL)
       			{
		            printk(KERN_WARNING"getLinkStatusTimerFn(): NCSI(%s) ERROR: Unable to allocate memory for the work queue item\n", 
					info->dev->name);
		            return;
       			}
				
			memset(work, 0, sizeof(GetLinkStatusReq_T));
#ifndef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES
		        INIT_WORK((struct work_struct *)work, NCSI_CheckStatusAndResetNCSI);
#else
		        INIT_WORK((struct work_struct *)work, NCSI_MultiPackageCheckStatus);
#endif
			
		        strncpy(work->InterfaceName, info->dev->name, sizeof(work->InterfaceName));

			work->PackageId = info->EnabledPackageID;
		        work->ChannelId = info->EnabledChannelID;
		        queue_work(ncsi_wq, (struct work_struct *)work);
		}
	}
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0))
static void
getLinkStatusTimerFn(unsigned long data)
{
	InvokeCallbackForEachInterface(CheckLinkStatus);

	// Respawning the timer
	getLinkStatusTimer.expires = jiffies + (CONFIG_SPX_FEATURE_NCSI_TIMER_DEALAY_FOR_GET_LINK_STATUS * HZ);
	add_timer(&getLinkStatusTimer);
}
#else
static void
getLinkStatusTimerFn(struct timer_list *t)
{
	InvokeCallbackForEachInterface(CheckLinkStatus);

	// Respawning the timer
	mod_timer(&getLinkStatusTimer, jiffies + CONFIG_SPX_FEATURE_NCSI_TIMER_DEALAY_FOR_GET_LINK_STATUS * HZ);
}
#endif

#endif
static void
NCSI_SwitchPackage(struct work_struct *data)
{
    GetLinkStatusReq_T *work;

    NCSI_IF_INFO *info;
    UINT8 PackageID;
    int i;
	
    if(data == NULL)
        return;

    work = (GetLinkStatusReq_T *) data;
    info = GetInterfaceInfoByName(work->InterfaceName);

    if(info != NULL)
    {
        netif_carrier_on(info->dev);    //make sure we can transmit

            for(i = 0; i < info->TotalChannels; i++)
            {
                if (info->ChannelInfo[i].Valid == 0)
                    continue;
		if (all_ch_link_down == 0)
		    break;
                PackageID = info->ChannelInfo[i].PackageID;
        	Check_PackageID(info,PackageID);
            }
    }

    kfree((void *)data);
    return;
}

void SwitchPackage ( NCSI_IF_INFO *info )
{
	GetLinkStatusReq_T *work = NULL;

	if(netif_running(info->dev))
	{
		if (InitComplete == 1)
		{
			work = (GetLinkStatusReq_T *) kmalloc(sizeof(GetLinkStatusReq_T), GFP_ATOMIC);

		        if(work == NULL)
       			{
		            printk(KERN_WARNING "SwitchPackage(): NCSI(%s) ERROR: Unable to allocate memory for the work queue item\n", 
					info->dev->name);
		            return;
       			}

			memset(work, 0, sizeof(GetLinkStatusReq_T));
		        INIT_WORK((struct work_struct *)work, NCSI_SwitchPackage);
			
		        strncpy(work->InterfaceName, info->dev->name, sizeof(work->InterfaceName));

		        queue_work(ncsi_wq, (struct work_struct *)work);
		}
	}

}

/*
 * @Brief : Periodically switch package to receive AEN from channel in different packages.
 *          Start when all channels link down, stop when any channel link up.
 */
static void
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0))
switchTimerFn(unsigned long data)
#else
switchTimerFn(struct timer_list *timer)
#endif
{
	if( all_ch_link_down == 1 )
	{
		InvokeCallbackForEachInterface(SwitchPackage);

		// Respawning the timer
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0))
		switchTimer.expires = jiffies + (5 * HZ);
		add_timer(&switchTimer);
#else
		mod_timer(&switchTimer, jiffies + (5 * HZ));
#endif
	}
}

static
int
EnableChannel(NCSI_IF_INFO *info, UINT8 PackageID, UINT8 ChannelID)
{
	UINT8   VlanMode/*, HwArbit = 0*/;

#ifdef CONFIG_SPX_FEATURE_NCSI_DISABLE_HW_ARBITRATION
//	HwArbit = 1;
#endif
	
#if 0
	/* Issue Select Package with Hw Arbit Enable from PRJ */
	if (NCSI_Issue_SelectPackage(info,PackageID,HwArbit) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Select Package (Hw Arbit Enable)Failed\n",
					info->dev->name,PackageID, ChannelID);	
		return 1;
	}
#endif

	if (NCSI_Issue_ClearInitialState(info,PackageID,ChannelID) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Clear Init State Failed\n",
					info->dev->name,PackageID, ChannelID);	
		return 1;
	}

	/* Setup VLANID */
	if(info->vlanID) 	//This call is to bring up the VLAN H/W filetring
	{
		if (NCSI_Issue_SetVLANFilter(info,PackageID,ChannelID,info->vlanID,1) != 0)
		{
			printk(KERN_DEBUG "NCSI(%s):%d.%d Setting VLAN TAG %d Failed\n",info->dev->name,PackageID, ChannelID,info->vlanID);
		}
		VlanMode=VLAN_MODE_VLAN_ONLY;	//In VLAN mode - only VLAN packets allowed. VLAN filtering done here.
	}
	else
	{
		VlanMode=VLAN_MODE_ANY_VLAN_NON_VLAN;		//In VLAN mode - VLAN and NON_VLAN (LAN) packets allowed.
	}

	/* Enable VLANID filter or Cleanup VLAN filter */
	if (NCSI_Issue_EnableVLAN(info,PackageID,ChannelID,VlanMode) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d VLAN filter enable failed\n",info->dev->name,PackageID, ChannelID);
	}

#if 0
	/* Issue an Enable TX for the channel */
	if (NCSI_Issue_ChannelCommands(info,CMD_ENABLE_CHANNEL_TX,PackageID,ChannelID) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Enable Channel Tx Failed\n",
					info->dev->name,PackageID, ChannelID);	
		return 1;
	}
#endif
		
	/* Enable the channel */
	if (NCSI_Issue_ChannelCommands(info,CMD_ENABLE_CHANNEL,PackageID,ChannelID) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Enable Channel Failed\n",
					info->dev->name,PackageID, ChannelID);	
		return 1;
	}

	printk(KERN_DEBUG "NCSI(%s): Channel %d.%d Enabled\n", info->dev->name, PackageID, ChannelID);

	info->EnabledPackageID = PackageID;
	info->EnabledChannelID = ChannelID;	

#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS) ||\
	defined(CONFIG_SPX_FEATURE_POLL_FOR_ASYNC_RESET )

#if defined(CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS) &&\
        !defined(CONFIG_SPX_FEATURE_POLL_FOR_ASYNC_RESET )

#ifndef CONFIG_SPX_FEATURE_DISABLE_AEN_SUPPORT
	if (info->IANA_ManID == VENDOR_ID_INTEL || info->IANA_ManID == VENDOR_ID_MARVELL)
		info->AENEnabled = CheckAENSupport(info, PackageID, ChannelID);
	else
#endif
		info->AENEnabled = 0;

	if ( info->AENEnabled )
		return 0;

#endif

	/* Initiate the timer only once; This will run always until the NCSI driver gets unloaded */
	if( !isPollTimerInitialized )  
	{
		printk("NCSI(%s): Initializing the Timer for getting the link state(Pkg:%d, Ch:%d).\n", info->dev->name, PackageID, ChannelID);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0))
		init_timer(&getLinkStatusTimer);
		getLinkStatusTimer.data = (unsigned long)info;
		getLinkStatusTimer.function = getLinkStatusTimerFn;
		getLinkStatusTimer.expires = jiffies + (CONFIG_SPX_FEATURE_NCSI_TIMER_DEALAY_FOR_GET_LINK_STATUS * HZ);
		add_timer(&getLinkStatusTimer);
#else
		timer_setup(&getLinkStatusTimer, getLinkStatusTimerFn, 0); 
		mod_timer(&getLinkStatusTimer, jiffies + CONFIG_SPX_FEATURE_NCSI_TIMER_DEALAY_FOR_GET_LINK_STATUS * HZ);
#endif
		isPollTimerInitialized = 1;
	}
	else {
		if(verbose & (SHOW_LINK_INFO | SHOW_MESSAGES))
			printk("NCSI(%s): Timer already initialized for getting the link state \n", info->dev->name );
	}
#endif

	return 0;
}

static
int
EnableChannelTx(NCSI_IF_INFO *info, UINT8 PackageID, UINT8 ChannelID)
{
	if (NCSI_Issue_ChannelCommands(info,CMD_ENABLE_CHANNEL_TX,PackageID,ChannelID) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Enable Channel Tx Failed\n",
					info->dev->name,PackageID, ChannelID);	
		return 1;
	}
	return 0;
}

static
int
DisableChannel(NCSI_IF_INFO *info, UINT8 PackageID, UINT8 ChannelID)
{
//	UINT8   HwArbit = 0;

#ifdef CONFIG_SPX_FEATURE_NCSI_DISABLE_HW_ARBITRATION
//	HwArbit = 1;
#endif

#if 0
	/* Issue Select Package with Hw Arbit Enable from PRJ */
	if (NCSI_Issue_SelectPackage(info,PackageID,HwArbit) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Select Package (Hw Arbit Enable)Failed\n",
					info->dev->name,PackageID, ChannelID);	
		return 1;
	}
#endif

	if (NCSI_Issue_ClearInitialState(info,PackageID,ChannelID) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Clear Init State Failed\n",
					info->dev->name,PackageID, ChannelID);	
		return 1;
	}

	/* Issue an DISABLE TX for the channel */
	if (NCSI_Issue_ChannelCommands(info,CMD_DISABLE_CHANNEL_TX,PackageID,ChannelID) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Disable Channel Tx Failed\n",
					info->dev->name,PackageID, ChannelID);
		return 1;
	}
		
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,4,11))
	/* Disable the channel */
	if (NCSI_Issue_DisableChannel(info,PackageID,ChannelID,0) != 0)
	{
		printk(KERN_DEBUG "NCSI(%s):%d.%d Disable Channel Failed\n",
					info->dev->name,PackageID, ChannelID);
		return 1;
	}
#endif

	printk(KERN_DEBUG "NCSI(%s): Channel %d.%d Disabled\n", info->dev->name, PackageID, ChannelID);


	return 0;
}

void
NCSI_Detect(struct work_struct *data)
{
	NCSI_IF_INFO *info;

	//info = (NCSI_IF_INFO *)data;
	info = container_of(data, NCSI_IF_INFO, detect_work);

	while (InitComplete == 0)
	{
		if(verbose & SHOW_MESSAGES)
		{
			printk ("NCSI : Initialization in progress, please wait...\n");
		}
		msleep(1000);
	}
	InitComplete = 0;
	NCSI_Detect_Info(info);
	return;
}

int
NCSI_Change_MacAddr(struct net_device *dev)
{
	UINT8 MACAddr[6];
	NCSI_IF_INFO *info;
	int index, enable_index=0;
	int flags;
	int reportlink=0;

	/* Get the curent MAC Address of the device */
	/*NCSI Need in the reverse order */
	MACAddr[0] = dev->dev_addr[5];
	MACAddr[1] = dev->dev_addr[4];
	MACAddr[2] = dev->dev_addr[3];
	MACAddr[3] = dev->dev_addr[2];
	MACAddr[4] = dev->dev_addr[1];
	MACAddr[5] = dev->dev_addr[0];
	if ((MACAddr[0] == 0) && (MACAddr[1] == 0) && (MACAddr[2] == 0) &&
	    (MACAddr[3] == 0) && (MACAddr[4] == 0) && (MACAddr[5] == 0))
	{
		printk("NCSI(%s): Error! Mac Address is 0. Cannot enable NCSI\n",dev->name);
		return -1;
	}

	info = GetInterfaceInfo(dev);
	if (info == NULL)
		return -1;

	/* if the interface is not NCSI, return */
	if (info->TotalChannels == 0)
		return -1;

	if(!netif_carrier_ok(dev))
	{
		reportlink = 1;
		netif_carrier_on(dev);
	}

	printk(KERN_DEBUG "NCSI(%s): Changing MAC Addr to  %02X:%02X:%02X:%02X:%02X:%02X\n",dev->name,
		MACAddr[5],MACAddr[4],MACAddr[3],MACAddr[2],MACAddr[1],MACAddr[0]);

	if(rtnl_trylock() == 0)
	{	
		flags = dev->flags;
		if (!(flags & IFF_UP))
  		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0))
       		dev_open(dev,NULL);
        #else
        	dev_open(dev);
        #endif
	}
	else
	{
		flags = dev->flags;
		if (!(flags & IFF_UP))	
	    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0))
        	dev_open(dev,NULL);
        #else
        	dev_open(dev);
        #endif
	}

	
	for (index = 0; index < info->TotalChannels ; index ++)
	{
		/*  
		 * Comment out enabled checking to set MAC address for all channel.
		 * When bonding is enabled and using eth0's MAC address.
		 * If other NCSI channel is still using its own MAC, 
		 * then connection will loss after change NCSI channel.
		 */
		 /*
		if (info->ChannelInfo[index].Enabled == 0)
			continue;
		*/
		if (info->ChannelInfo[index].Enabled)
			enable_index = index;

		if (NCSI_Issue_SetMacAddress(info,info->ChannelInfo[index].PackageID,info->ChannelInfo[index].ChannelID,
					MACAddr,1,0) != NCSI_ERR_SUCCESS)
		{
			printk("NCSI(%s): ERROR: Change Mac Address(%d.%d) Failed \n",dev->name,info->ChannelInfo[index].PackageID,
								info->ChannelInfo[index].ChannelID);
		}
		else
		{
			printk(KERN_DEBUG "NCSI(%s): Change  Mac Address(%d.%d) Passed \n",dev->name,info->ChannelInfo[index].PackageID,
								info->ChannelInfo[index].ChannelID);
		}
	
	}

	Check_PackageID(info, info->ChannelInfo[enable_index].PackageID);

	if(reportlink)
		InitEthtoolInfo(info);
	
	if (!(flags & IFF_UP))	
		dev_close(dev);

	return 0;
}

void NSCI_Detect_Channel (NCSI_IF_INFO *info, UINT8 PackageID, UINT8 ChannelID)
{
    int i;
    UINT32 Ver1,Ver2,Ver3;
    UINT8 Major;
    struct net_device *dev;
    
    dev  = info->dev;
    
    /* Issue Cleear Init State  for each channel */
    if (NCSI_Issue_ClearInitialState(info,PackageID,ChannelID) != 0)
    {
        return;
    }

    /* Get Version ID and verify it is > 1.0  */
    if (NCSI_Issue_GetVersionID(info,PackageID,ChannelID,&Ver1,&Ver2,&Ver3) != 0)
    {
        printk("NCSI(%s):%d.%d Get Version IDFailed\n",dev->name,PackageID, ChannelID); 
        return;
    }

    printk("Manufacturer ID :: (0x%08lx)\n", Ver3);	
    Major = (Ver1 >> 24) & 0xFF;
    if ((Major & 0xF0)== 0xF0)
        Major = Major & 0x0F;
    if (Major < 1)
    {
        printk(KERN_DEBUG "NCSI(%s):%d.%d Version(0x%08lx) is < 1.0  Not supported\n",
                dev->name,PackageID, ChannelID,Ver1);
        return;
    }

    for(i = 0; i < info->TotalChannels; i++)
    {
        if ((PackageID == info->ChannelInfo[i].PackageID) && 
                (ChannelID == info->ChannelInfo[i].ChannelID))
        {
            printk (KERN_DEBUG "NCSI(%s):%d.%d ChannelID and PackageID found in %d\n", 
                    dev->name, PackageID, ChannelID, i);
            break;
        }
    }
    
    if (i == info->TotalChannels)
    {
        i = info->TotalChannels;
        info->TotalChannels++;
    }
    
    /* Get Capabilities and set ArbitSupport */
    if (NCSI_Issue_GetCapabilities(info,PackageID,ChannelID, 
    		&info->ChannelInfo[i].Caps, &info->ChannelInfo[i].AENCaps, &ChannelCount[PackageID]) != 0)
    {
        printk(KERN_DEBUG "NCSI(%s):%d.%d Get Capabilities Failed\n", dev->name, PackageID, ChannelID);
        ChannelCount[PackageID] = MAX_CHANNEL_ID;
        return;
    }
    
    if (info->ChannelInfo[i].Caps & HW_ARBITRATION_SUPPORT)
        info->ChannelInfo[i].ArbitSupport = 1;
    else
        info->ChannelInfo[i].ArbitSupport = 0;

    info->ChannelInfo[i].PackageID = PackageID;
    info->ChannelInfo[i].ChannelID = ChannelID;
    info->IANA_ManID = Ver3;
    printk(KERN_DEBUG "NCSI(%s):Found NC-SI at Package:Channel (%d:%d)\n", dev->name,PackageID,ChannelID);

    return;
}

void NCSI_Configure_Channel (NCSI_IF_INFO *info, UINT8 PackageID, UINT8 ChannelID)
{
    UINT8 MACAddr[6];
    struct net_device *dev;
    int retval, i;
#ifndef CONFIG_SPX_FEATURE_NCSI_FORCE_LAN_SPEED_10G
    int NcsiSpeed = 0, NcsiDuplex = 0;
#endif
    UINT32 Caps, AENCaps;
    UINT8	ChannelCount;

    dev  = info->dev;
    /* Get MAC Address to use */
    /*NCSI Need in the reverse order */
    MACAddr[0] = dev->dev_addr[5];
    MACAddr[1] = dev->dev_addr[4];
    MACAddr[2] = dev->dev_addr[3];
    MACAddr[3] = dev->dev_addr[2];
    MACAddr[4] = dev->dev_addr[1];
    MACAddr[5] = dev->dev_addr[0];

    if ((MACAddr[0] == 0) && (MACAddr[1] == 0) && (MACAddr[2] == 0) &&
        (MACAddr[3] == 0) && (MACAddr[4] == 0) && (MACAddr[5] == 0))
    {
        printk("NCSI(%s): Error! Mac Address is 0. Cannot enable NCSI\n",dev->name);
        return;
    }
    
    /* Issue Cleear Init State to enter into init state  */
    if (NCSI_Issue_ClearInitialState(info,PackageID,ChannelID) != 0)
    {
        printk("NCSI(%s):%d.%d Clear Init State Failed\n",dev->name,PackageID, ChannelID);  
        return;
    }

    /* Issue a Reset Channel to clear all previous config */
    if (NCSI_Issue_ResetChannel(info,PackageID,ChannelID) != 0)
    {
        printk("NCSI(%s):%d.%d Reset Channel Failed\n",dev->name,PackageID, ChannelID); 
        return;
    }

    /* Issue Cleear Init State to enter into init state  */
    if (NCSI_Issue_ClearInitialState(info,PackageID,ChannelID) != 0)
    {
        printk("NCSI(%s):%d.%d Clear Init State Failed\n",dev->name,PackageID, ChannelID);  
        return;
    }

#ifndef CONFIG_SPX_FEATURE_DISABLE_SETTING_VETO_BIT_DURING_INIT
	switch (info->IANA_ManID)
	{
	
	case VENDOR_ID_INTEL:	//For Intel Management Controller
	    printk(KERN_DEBUG "NCSI(%s):%d.%d %d Set Intel Management Control\n",info->dev->name,PackageID, ChannelID,info->VetoBit);
	    // Enable/Disable Keep Phy Link Up feature for Intel GbE Controller
        if (NCSI_Issue_OEM_SetIntelManagementControlCommand(info,PackageID, ChannelID, info->VetoBit) != 0)
        {
	    	printk(KERN_DEBUG "NCSI(%s):%d.%d Set Intel Management Control Failed\n",info->dev->name,PackageID, ChannelID); 
        }
	break;
		
	default:
		printk(KERN_DEBUG ">>>>>>>>>NCSI Management Control is not supported<<<<<<<<<<<<\n");
	break;
	}
#endif

    /* Setup MAC Address */
    if (NCSI_Issue_SetMacAddress(info,PackageID,ChannelID,MACAddr,1,0) != 0)
    {
        printk(KERN_DEBUG "NCSI(%s):%d.%d Set Mac Address Failed\n",dev->name,PackageID, ChannelID);   
        return;
    }

#if 0
    /* Setup VLANID */
    printk("NCSI(%s):%d.%d Setting VLAN in NCSI with VLAN TAG %d ...\n",dev->name,PackageID,ChannelID,CFG_PROJ_VLAN_ID);
    if (NCSI_Issue_SetVLANFilter(info,PackageID,ChannelID,CFG_PROJ_VLAN_ID,1) != 0)
    {
        printk("NCSI(%s):%d.%d Setting VLAN TAG %d Failed\n",dev->name,PackageID, ChannelID,CFG_PROJ_VLAN_ID);
        return;
    }
    
    /* Enable VLANID filter */
    if (NCSI_Issue_EnableVLAN(info,PackageID,ChannelID,VLAN_MODE_ANY_VLAN_NON_VLAN) != 0)
    {
        printk("NCSI(%s):%d.%d VLAN filter enable failed\n",dev->name,PackageID, ChannelID);    
        return;
    }
    printk("NCSI(%s):%d.%d Setting VLAN in NCSI is completed with VLAN TAG %d\n",dev->name,PackageID,ChannelID,CFG_PROJ_VLAN_ID);
#endif

    /* Enable Broaccast filter */
    if (NCSI_Issue_EnableBcastFilter(info,PackageID,ChannelID,1,1,1,1) != 0)
    {
        printk("NCSI(%s):%d.%d Enable Bcast Filter Failed\n",dev->name,PackageID, ChannelID);   
        return;
    }

#ifdef CONFIG_SPX_FEATURE_NCSI_FLOW_CONTROL
	/*Issue set Flow Control Command with Enable Bidirectional Flow Control*/
	if(NCSI_Issue_SetNCSIFlowControl(info,PackageID,ENABLE_BI_DIR_FLOW_CONTROL) != 0)
		printk("NCSI(%s):%d Set Flow Control\n",dev->name,PackageID);
#endif
	
    /* Disable Multicast filter */
    if (NCSI_Issue_DisableMcastFilter(info,PackageID,ChannelID) != 0)
    {
        printk("NCSI(%s):%d.%d Disable Multicast Filter Failed\n",dev->name,PackageID, ChannelID);
    }

#ifndef CONFIG_SPX_FEATURE_DISABLE_AEN_SUPPORT
    if (info->IANA_ManID == VENDOR_ID_INTEL || info->IANA_ManID == VENDOR_ID_MARVELL)
    {
    	if (NCSI_Issue_GetCapabilities(info,(UINT8)PackageID,(UINT8)ChannelID, &Caps, &AENCaps, &ChannelCount) != 0)
    	{
    		printk("NCSI(%s):%d.%d Get Capabilities Failed\n", dev->name, PackageID, ChannelID);
    		return;
    	}

        /* Setup AEN Messages */
    	if (NCSI_Issue_EnableAEN(info,(UINT8)PackageID,(UINT8)ChannelID,AENCaps&LINK_STATUS_CHANGE_CONTROL_AEN,
    	    	AENCaps&REQUIRED_CONTROL_AEN, AENCaps&HOST_NC_DRIVER_STATUS_CHANGE_CONTROL_AEN) != 0)
        {
#ifndef CONFIG_SPX_FEATURE_NCSI_GET_LINK_STATUS_FOR_NON_AEN_SUPPORTED_CONTROLLERS
            printk("NCSI(%s):%d.%d Enable AEN Failed\n",dev->name,PackageID, ChannelID);
            return;
#endif
        }
    }
#endif

    if (EnableSetLink != 0)
    {
#ifdef CONFIG_SPX_FEATURE_NCSI_FORCE_LAN_SPEED_10G
    	retval = NCSI_Issue_SetLink(info,(UINT8)PackageID,(UINT8)ChannelID,0/*Force Speed*/,LINK_ENABLE_10_GBPS,LINK_ENABLE_FULL_DUPLEX) ;
#else
    	/* Enable Auto Negotiation */
    	if (UserSpeed == 0)   /* Auto Neg */
    	{
    		retval = NCSI_Issue_SetLink(info,(UINT8)PackageID,(UINT8)ChannelID,1,0,0);
    	}
		else
		{
			if (UserSpeed == 10)
				NcsiSpeed =  LINK_ENABLE_10_MBPS;
			if (UserSpeed == 100)
				NcsiSpeed =  LINK_ENABLE_100_MBPS;
			if (UserSpeed == 1000)
				NcsiSpeed =  LINK_ENABLE_1000_MBPS;
			if (UserSpeed == 10000)
				NcsiSpeed =  LINK_ENABLE_10_GBPS;
	
			if (UserDuplex == 1)
				NcsiDuplex =  LINK_ENABLE_FULL_DUPLEX;
			if (UserDuplex == 0)
				NcsiDuplex =  LINK_ENABLE_HALF_DUPLEX;
	
			retval = NCSI_Issue_SetLink(info,(UINT8)PackageID,(UINT8)ChannelID,UserAutoNeg,NcsiSpeed,NcsiDuplex);
		}
#endif    	
    } else {
		retval = 0;
	}

    if (retval == 0) 
    {   
        /* Wait for one second for Set Link to complete */
        msleep(1000);
    }
    else
    {
        if (retval == NCSI_ERR_CONFLICT)
            printk("NCSI(%s): %d.%d Set Link Conflict\n",dev->name,PackageID, ChannelID);
        else
        {
            printk("NCSI(%s): %d.%d Set Link Failed\n",dev->name,PackageID, ChannelID);
        }
    }

    for(i = 0; i < info->TotalChannels; i++)
    {
        if ((PackageID == info->ChannelInfo[i].PackageID) && 
                (ChannelID == info->ChannelInfo[i].ChannelID))
        {
            /* Set this channel info is setup */ 
             info->ChannelInfo[i].Valid = 1;
        }
    }
    return;
}

void NSCI_Detect_Package_Channel (NCSI_IF_INFO *info, UINT8 PackageID, UINT8 ChannelID)
{

    UINT8  HwArbit = 0, i;

#ifdef CONFIG_SPX_FEATURE_NCSI_DISABLE_HW_ARBITRATION
    HwArbit = 1;
#endif
    /* Blindly deselect all  packages. */
    for (i = 0; i < MAX_PACKAGE_ID; i++)
        NCSI_Issue_DeSelectPackage(info,i);
    
    /* Issue Select Package with Hw Arbit Enable from PRJ */
    if (NCSI_Issue_SelectPackage(info,PackageID,HwArbit) != 0)
    {
        return;
    }
    
    NSCI_Detect_Channel (info, PackageID, ChannelID);
    NCSI_Configure_Channel (info, PackageID, ChannelID);
    
    /* Deselect previusly selected package */
    NCSI_Issue_DeSelectPackage(info,PackageID);
}

void
NCSI_Detect_Info(NCSI_IF_INFO *info)
{
	struct net_device *dev;

	UINT8 PrevPackageID;
	UINT8 PackageID;
	UINT8 ChannelID;
	UINT8 MACAddr[6];
	int i;

	UINT8   HwArbit = 0;

#ifdef CONFIG_SPX_FEATURE_NCSI_DISABLE_HW_ARBITRATION
	HwArbit = 1;
#endif
	ValidPackages = 0;

	dev  = info->dev;

	/* Get MAC Address to use */
	/*NCSI Need in the reverse order */
	//memcpy(&MACAddr[0],dev->dev_addr,6);
	MACAddr[0] = dev->dev_addr[5];
	MACAddr[1] = dev->dev_addr[4];
	MACAddr[2] = dev->dev_addr[3];
	MACAddr[3] = dev->dev_addr[2];
	MACAddr[4] = dev->dev_addr[1];
	MACAddr[5] = dev->dev_addr[0];
	printk(KERN_DEBUG "NCSI(%s): MAC Addr = %02X:%02X:%02X:%02X:%02X:%02X\n",dev->name,
		MACAddr[5],MACAddr[4],MACAddr[3],MACAddr[2],MACAddr[1],MACAddr[0]);
					
	if ((MACAddr[0] == 0) && (MACAddr[1] == 0) && (MACAddr[2] == 0) &&
	    (MACAddr[3] == 0) && (MACAddr[4] == 0) && (MACAddr[5] == 0))
	{
		printk("NCSI(%s): Error! Mac Address is 0. Cannot enable NCSI\n",dev->name);
		return;
	}

	info->TotalChannels = 0;
	/* Blindly deselect all  packages, except package ID 0 as it will be selected in the next loop. */
	for (PackageID = 1; PackageID < MAX_PACKAGE_ID; PackageID++)
		NCSI_Issue_DeSelectPackage(info,PackageID);

	/* Discover Packages and Channels */
	for (PackageID = 0; PackageID < MAX_PACKAGE_ID; PackageID++)
	{
		ChannelCount[PackageID] = MAX_CHANNEL_ID;

		/* Issue Select Package with Hw Arbit Disable*/
		if (NCSI_Issue_SelectPackage(info,PackageID,HwArbit) != 0)
			continue;
		
		/* Find the number of channels support by this packages */
		for (ChannelID = 0; ChannelID < ChannelCount[PackageID]; ChannelID++)
		{
			NSCI_Detect_Channel (info, PackageID, ChannelID);
		}
		
		/* Deselect previusly selected package */
		NCSI_Issue_DeSelectPackage(info,PackageID);
	}

	if (info->TotalChannels == 0)
		printk(KERN_DEBUG "NCSI(%s): No NCSI Interfaces detected\n", dev->name);


	PrevPackageID = -1;
	/* Configure the detected channels */
	for(i=0;i<info->TotalChannels;i++)
	{
		PackageID = info->ChannelInfo[i].PackageID;
		ChannelID = info->ChannelInfo[i].ChannelID;

		/* Issue Select Package with Hw Arbit Disable*/
		if (NCSI_Issue_SelectPackage(info,PackageID,HwArbit) != 0)
			continue;
		
		NCSI_Configure_Channel (info, PackageID, ChannelID);
		
		/* Count the number of valid packages*/
		if (PrevPackageID != PackageID)
		{
			ValidPackages++;
			PrevPackageID = PackageID;
		}
		/* Deselect previusly selected package */
		NCSI_Issue_DeSelectPackage(info,PackageID);
	}

	if (ValidPackages > 1)
	{
		printk(KERN_DEBUG "NCSI(%s):Multiple Packages Found\n",dev->name);
		for(i=0;i<info->TotalChannels;i++)
		{
			if (info->ChannelInfo[i].Valid == 0)
				continue;
			if (info->ChannelInfo[i].ArbitSupport == 0)
			{
				PackageID = info->ChannelInfo[i].PackageID;
				ChannelID = info->ChannelInfo[i].ChannelID;
				printk(KERN_DEBUG "NCSI(%s):WARNING: Channel (%d:%d) does not support Arbitration\n",
							dev->name,PackageID,ChannelID);
			}	
		}
	}

	if ((info->TotalChannels) && (ValidPackages))
		 NCSI_Net_Driver_Register(info);

	return;
}

static int NCSI_Enable_Ex(struct work_struct *data)
{
	NCSI_IF_INFO *info;
	int retry = 5, ret = 0, i;
	UINT32 ConfigFlags = 0;
	UINT32 AENControl = 0;
	UINT8 PackageID = 0xFF;
	UINT8 ChannelID = 0xFF;
	info = container_of(data, NCSI_IF_INFO, enable_work);
		
	ret = NCSI_Enable_Info(info);
	//Verify Enable Channel Command 
	while (retry)
	{		
		retry--;
		for(i=0;i<info->TotalChannels;i++)
		{			
			if (info->ChannelInfo[i].Enabled == 0)
				continue;

			PackageID = info->ChannelInfo[i].PackageID;
			ChannelID = info->ChannelInfo[i].ChannelID;
		}
		
		//No port Enabled
		if((PackageID == 0xFF) && (ChannelID == 0xFF)){
			break;
		}			
		
		if(NCSI_Issue_GetParameters(info, PackageID, ChannelID, &ConfigFlags, &AENControl) == NCSI_ERR_SUCCESS)
		{
			if ((ConfigFlags & 0x6) == 0x6) // Verify whether Channel Enabled and Channel Network TX Enabled.
			{			
				//Enable Channel success
				break;
			}
			else{
				printk ("NCSI(%d:%d) - Enable Channel Failed, retry the complete Init sequence.\n", PackageID, ChannelID);
				NSCI_Detect_Package_Channel(info, PackageID, ChannelID);
				//Try Enable channel again
				ret = NCSI_Enable_Info(info);
			}
		}
	}
 
	return ret;
}

int
NCSI_Enable_Info(NCSI_IF_INFO *info)
{
	int i, enabled = 0;
	UINT8 PackageID;
	UINT8 ChannelID;
	UINT32 LinkStatus;

	if(!info->TotalChannels)
		return 1;

	netif_carrier_on(info->dev);//make sure we can transmit

	/* Check for User Specified channel */
	if (!info->AutoSelect) //0
	{
		for(i=0;i<info->TotalChannels;i++)
		{
			if (info->ChannelInfo[i].Valid == 0)
				continue;

			PackageID = info->ChannelInfo[i].PackageID;
			ChannelID = info->ChannelInfo[i].ChannelID;
			if ((ChannelID != info->ForceChannel) || (PackageID != info->ForcePackage)){//other than user requested channel
				if (info->ChannelInfo[i].Enabled == 1)//any other chn enabled
				{
					if (DisableChannel(info,PackageID,ChannelID) == 0){
						info->ChannelInfo[i].Enabled = 0;
						continue;
					}
				}
			}
		}
		
		for(i=0;i<info->TotalChannels;i++)
		{
			if (info->ChannelInfo[i].Valid == 0)
				continue;

			PackageID = info->ChannelInfo[i].PackageID;
			ChannelID = info->ChannelInfo[i].ChannelID;
			
			if ((PackageID == info->ForcePackage) && (ChannelID == info->ForceChannel))
			{
				if (EnableChannel(info,PackageID,ChannelID) != 0 || EnableChannelTx(info,PackageID,ChannelID) != 0)
					return 1;   /* Failed User Values */
				info->ChannelInfo[i].Enabled = 1;
				InitEthtoolInfo(info);
				return 0;
			}
		}
		printk(KERN_DEBUG "NCSI(%s): Unable to Enable User Config. Default to auto\n",info->dev->name);
	}

	/* If Auto Select or user specified is invalid */
	if (info->AutoSelect == 1)
	{
		//Enable every channel first
		for(i=0;i<info->TotalChannels;i++)
		{
			if (info->ChannelInfo[i].Valid == 0)
				continue;
			PackageID = info->ChannelInfo[i].PackageID;
			ChannelID = info->ChannelInfo[i].ChannelID;
#ifdef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES
			DisableChannel(info,PackageID,ChannelID);
			info->ChannelInfo[i].Enabled = 0;
#else
			EnableChannel(info,PackageID,ChannelID);
#endif
		}
		
//		/* Blindly deselect all  packages. */
//		for (PackageID = 0; PackageID < MAX_PACKAGE_ID; PackageID++)
//			NCSI_Issue_DeSelectPackage(info,PackageID);
	}
	for(i=0;i<info->TotalChannels;i++)
	{
		if (info->ChannelInfo[i].Valid == 0)
			continue;

#ifdef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES		
		if (enabled == 1)
			continue;
#endif

		PackageID = info->ChannelInfo[i].PackageID;
		ChannelID = info->ChannelInfo[i].ChannelID;
		if(info->AutoSelect)
		{
			msleep(1000);  //Adding a delay of 1 second before issuing GetLinkStatus command to get the proper link status
			/* Get Link Status to check if Channel can be enabled */	
			if (NCSI_Issue_GetLinkStatus(info,(UINT8)PackageID,(UINT8)ChannelID,&LinkStatus) != 0)
			{
				continue;
			}
			if (!(LinkStatus & 0x01))
			{
#ifndef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES
				//Disable channel TX with unlink port
				DisableChannel(info,PackageID,ChannelID);
				info->ChannelInfo[i].Enabled = 0;
#endif
				continue;
			}
		}
		
#ifdef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES
		if (EnableChannel(info,PackageID,ChannelID) == 0 && EnableChannelTx(info,PackageID,ChannelID) == 0)
#else
		if((LinkStatus & 0x01) && (enabled == 0))
#endif
		{
			enabled = 1;
			info->ChannelInfo[i].Enabled = 1;
#ifndef CONFIG_SPX_FEATURE_NCSI_SUPPORT_MULTI_PACKAGES
			EnableChannelTx(info,PackageID,ChannelID);
#endif
			all_ch_link_down = 0;
			if (rtnl_trylock())
			{
				netdev_link_up(info->dev);
				rtnl_unlock();
			}
			else
			{
				netdev_link_up(info->dev);
			}
			InitEthtoolInfo(info);
		}else {
			DisableChannel(info,PackageID,ChannelID); //Disable channel TX with non-master port
			info->ChannelInfo[i].Enabled = 0;
		}
	}
	
	if(enabled) {
		return 0;
	}

	if (info->AutoSelect)
	{
		all_ch_link_down = 1;
#if 0
		// there is no connected NC-SI port or error in enabling
		for(i=0;i<info->TotalChannels;i++)
		{
			if (info->ChannelInfo[i].Valid == 0)
				continue;
			PackageID = info->ChannelInfo[i].PackageID;
			ChannelID = info->ChannelInfo[i].ChannelID;

			EnableChannel(info,PackageID,ChannelID);//enable every channel to receive aen
		}
		if (rtnl_trylock())
		{
			netdev_link_down(info->dev);
			rtnl_unlock();
		}
		else
		{
			netdev_link_down(info->dev);
		}
		InitEthtoolInfo(info);
#endif

	        if( ValidPackages > 1 )  
	        {
			if ( !isSwitchTimerInitialized )
			{
	        		printk("NCSI(%s): Initializing the timer for switch packages.\n", info->dev->name);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0))
	        		init_timer(&switchTimer);
	        		switchTimer.data = (unsigned long)info;
	        		switchTimer.function = switchTimerFn;
	        		switchTimer.expires = jiffies + (5 * HZ);
	        		add_timer(&switchTimer);
#else
					timer_setup(&switchTimer, switchTimerFn, 0);
					mod_timer(&switchTimer, jiffies + (5 * HZ)); 
#endif
	        		isSwitchTimerInitialized = 1;
			}
			else
			{
				//Respawning the timer
				
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0))
				switchTimer.expires = jiffies + (5 * HZ);
				add_timer(&switchTimer);
#else
				mod_timer(&switchTimer, jiffies + (5 * HZ));
#endif
			}
	        }
	}

	return 1;
}

void
NCSI_Enable(struct work_struct *data)
{
	NCSI_Enable_Ex(data);
	InitComplete = 1;
}

void
NCSI_Disable(struct work_struct *data)
{
	NCSI_IF_INFO *info;
	int i;
	UINT8 PackageID;
	UINT8 ChannelID;

	//info = (NCSI_IF_INFO *)data;
	info = container_of(data, NCSI_IF_INFO, disable_work); 

	for(i=0;i<info->TotalChannels;i++)
	{
		if (info->ChannelInfo[i].Valid == 0)
			continue;

		if (info->ChannelInfo[i].Enabled == 1)
		{
			PackageID = info->ChannelInfo[i].PackageID;
			ChannelID = info->ChannelInfo[i].ChannelID;
			if (DisableChannel(info,PackageID,ChannelID) == 0)
			{
				info->ChannelInfo[i].Enabled = 0;
				InitEthtoolInfo(info);
			}
		}
	}

	return;
}
	
static void 
NCSI_SetUserLink(struct work_struct *data)
{
	SetUserLinkReq_T *work;
	NCSI_IF_INFO *info;
	int NcsiSpeed= LINK_ENABLE_100_MBPS;
	int NcsiDuplex=LINK_ENABLE_FULL_DUPLEX;
	int retval;

	if (data == NULL) return;

	work = (SetUserLinkReq_T *)data;
	info = GetInterfaceInfoByName(work->InterfaceName);


	if (work->Speed == 10)
		NcsiSpeed =  LINK_ENABLE_10_MBPS;
	if (work->Speed == 100)
		NcsiSpeed =  LINK_ENABLE_100_MBPS;
	if (work->Speed == 1000)
		NcsiSpeed =  LINK_ENABLE_1000_MBPS;
        if (work->Speed == 10000)
		NcsiSpeed =  LINK_ENABLE_10_GBPS;

	if (work-> Duplex== 1)
		NcsiDuplex =  LINK_ENABLE_FULL_DUPLEX;
	if (work-> Duplex== 0)
		NcsiDuplex =  LINK_ENABLE_HALF_DUPLEX;
	
#ifdef CONFIG_SPX_FEATURE_NCSI_FORCE_LAN_SPEED_10G
	if (work->Speed == LINK_ENABLE_10_GBPS) 
	{
		retval = NCSI_Issue_SetLink(info,(UINT8)work->PackageId,(UINT8)work->ChannelId,0/*Force Speed*/,LINK_ENABLE_10_GBPS,NcsiDuplex) ;
		kfree ((void *)data);
		return;
	}
#endif
	if (info != NULL)
	{

		if (work->Speed == 0)	/* Auto Neg */
		{
			printk(KERN_DEBUG "NCSI(%s): Forcing  Link for AutoNegotiation\n", work->InterfaceName);
			retval = NCSI_Issue_SetLink(info,(UINT8)work->PackageId,(UINT8)work->ChannelId,1,0,0);
		}
		else
		{
			printk(KERN_DEBUG "NCSI(%s): Forcing  Link for %dMbps %s Duplex \n", work->InterfaceName,work->Speed, (work->Duplex)?"Full":"Half");
			retval = NCSI_Issue_SetLink(info,(UINT8)work->PackageId,(UINT8)work->ChannelId,work->AutoNeg,NcsiSpeed,NcsiDuplex);
		}
		if (retval == 0)
			printk(KERN_DEBUG "NCSI(%s): Forcing Link Success \n", work->InterfaceName);
	}
	else
		printk(KERN_DEBUG "NCSI : Setting User Link Failed. Invalid Interface (%s)\n", work->InterfaceName);

	kfree((void *)data);
	
	return;
}

#ifdef CONFIG_SPX_FEATURE_NCSI_MANUAL_DETECT
static void 
NCSI_SetUserDetect(struct work_struct *data)
{
    NCSI_IF_INFO *info = NULL;
    char interfaceName[MAX_IF_NAME_LEN+1];
    int i;
    
	while (InitComplete == 0)
	{
		if(verbose & SHOW_MESSAGES)
		{
			printk ("NCSI : Initialization in progress, please wait...\n");
		}
		msleep(1000);
	}
    InitComplete = 0;
    for (i = 0; i < MAX_NET_IF; i++)
    {
        sprintf(interfaceName,"eth%d",i);
        if (strstr (CONFIG_SPX_FEATURE_NCSI_INTERFACE_NAMES, interfaceName) != NULL)
        {
            printk (KERN_DEBUG"NCSI(%s): User Detect NCSI Packages and Channels\n", interfaceName);
            info = GetInterfaceInfoByName(interfaceName);

            if (info != NULL)
            {
                if(rtnl_trylock() == 1)
                {
			       	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0))
            		dev_open(info->dev,NULL);
        			#else
            		dev_open(info->dev);
        			#endif

                    netif_carrier_on(info->dev);//make sure we can transmit
                    rtnl_unlock();
                }
                else
                {
   					#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0))
                    dev_open(info->dev,NULL);
                    #else
                    dev_open(info->dev);
                    #endif

                    netif_carrier_on(info->dev);//make sure we can transmit
                }
                
                NCSI_Detect_Info(info);
            }
            
        }
    }
    InitComplete = 1;
    kfree((void *)data);
    return;
}
#endif

static void 
NCSI_SetMAC(struct work_struct *data)
{
	NCSI_IF_INFO *info = NULL;
	char interfaceName[MAX_IF_NAME_LEN] = { 0 };
	int i = 0;
	int flags = 0;

	for (i = 0; i < MAX_NET_IF; i++)
	{
		sprintf(interfaceName,"eth%d",i);
		if (strncmp (interfaceName, CONFIG_SPX_FEATURE_NCSI_DEFAULT_INTERFACE, sizeof(interfaceName)) == 0)
		{
			info = GetInterfaceInfoByName(interfaceName);
			if (info != NULL)
			{
				flags = info->dev->flags;

				if(rtnl_trylock() == 1)
				{
					if (!(flags & IFF_UP))
					{
						#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0))
						dev_open(info->dev,NULL);
						#else
						dev_open(info->dev);
						#endif
					}
					if(!netif_carrier_ok(info->dev))
					{
						netif_carrier_on(info->dev);//make sure we can transmit
					}

					rtnl_unlock();
				}
				else
				{
					if (!(flags & IFF_UP))
					{
						#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0))
						dev_open(info->dev,NULL);
						#else
						dev_open(info->dev);
						#endif
					}
					if(!netif_carrier_ok(info->dev))
					{
						netif_carrier_on(info->dev);//make sure we can transmit
					}
				}
			}

			for(i=0;i<info->TotalChannels;i++)
			{
				if (info->ChannelInfo[i].Valid == 0)
					continue;

				NCSI_Configure_Channel(info, info->ChannelInfo[i].PackageID, info->ChannelInfo[i].ChannelID);
			}
		}
	}
	kfree((void *)data);
	return;
}

static void
NCSI_SetUserSettings(struct work_struct *data)
{
	SetUserSettingsReq_T *work;
	NCSI_IF_INFO *info;

	if (data == NULL) return;

	work = (SetUserSettingsReq_T *)data;
	info = GetInterfaceInfoByName(work->InterfaceName);

	while (InitComplete == 0)
	{
		if(verbose & SHOW_MESSAGES)
		{
			printk ("NCSI : Initialization in progress, please wait...\n");
		}
		msleep(1000);
	}
	InitComplete = 0;
	
	if (info != NULL)
	{
		if( info->AutoSelect == work->AutoSelect &&
		 info->AutoSelect == 1 && info->vlanID == work->VLANId)
		{
			printk(KERN_DEBUG "NCSI: Same mode, do nothing\n");
			kfree((void *)data);

			InitComplete = 1;
			return;
		}
		info->vlanID = work->VLANId;
		info->AutoSelect = work->AutoSelect;
		if(!info->AutoSelect)
		{
			info->ForcePackage = work->PackageId;
			info->ForceChannel = work->ChannelId;
#ifdef CONFIG_SPX_FEATURE_NCSI_RESET_INTERFACE_IN_USER_SETTINGS
			if (UserInitEnabled == 1)
			{
				printk (KERN_DEBUG "NCSI(%s):(%d.%d) Reset for NCSI Interface..\n", 
						work->InterfaceName, work->PackageId, work->ChannelId);
				/* Detect and Configure the NC-SI Interface that 
				 * pluggable NCSI channels will also work */
				netif_carrier_on(info->dev);//make sure we can transmit
				NSCI_Detect_Package_Channel (info, work->PackageId, work->ChannelId);
				UserInitEnabled = 0;
			}
#endif
		}

		if (NCSI_Enable_Ex((struct work_struct*)&(info->enable_work)) == 1) 
			printk("NCSI(%s): Setting User Config Failed\n", work->InterfaceName);
	}
	else
		printk("NCSI : Setting User Config Failed. Invalid Interface (%s)\n", work->InterfaceName);
	InitComplete = 1;

	kfree((void *)data);
	
	return;
}

static void
NCSI_ReEnable(struct work_struct *data)
{
	SetUserSettingsReq_T *work;
	NCSI_IF_INFO *info;

	if (data == NULL) return;

	work = (SetUserSettingsReq_T *)data;
	info = GetInterfaceInfoByName(work->InterfaceName);

	while (InitComplete == 0)
	{
		if(verbose & SHOW_MESSAGES)
		{
			printk ("NCSI : Initialization in progress, please wait...\n");
		}
		msleep(1000);
	}
	InitComplete = 0;
		
	if (info != NULL)
	{
		info->vlanID = work->VLANId;
		info->AutoSelect = work->AutoSelect;
		if(!info->AutoSelect)
		{
			info->ForcePackage = work->PackageId;
			info->ForceChannel = work->ChannelId;
	#ifdef CONFIG_SPX_FEATURE_NCSI_RESET_INTERFACE_IN_USER_SETTINGS
			if (UserInitEnabled == 1)
			{
				printk (KERN_DEBUG "NCSI(%s):(%d.%d) Reset for NCSI Interface..\n", 
						work->InterfaceName, work->PackageId, work->ChannelId);
				/* Detect and Configure the NC-SI Interface that 
				 * pluggable NCSI channels will also work */
				netif_carrier_on(info->dev);//make sure we can transmit
				NSCI_Detect_Package_Channel (info, work->PackageId, work->ChannelId);
					UserInitEnabled = 0;
				}
	#endif
			}

			if (NCSI_Enable_Ex((struct work_struct*)&(info->enable_work)) == 1) 
				printk("NCSI(%s): Setting User Config Failed\n", work->InterfaceName);
		}
		else
			printk("NCSI : Setting User Config Failed. Invalid Interface (%s)\n", work->InterfaceName);
		InitComplete = 1;

		kfree((void *)data);
		
		return;
}

static void 
NCSI_SetUserVetoBit(struct work_struct *data)
{
	SetUserVetoBitReq_T *work;
	NCSI_IF_INFO *info;
	UINT32 Ver1,Ver2;
	static UINT32 Ver3 = 0;

	if (data == NULL) return;

	work = (SetUserVetoBitReq_T *)data;
	info = GetInterfaceInfoByName(work->InterfaceName);

	if (info != NULL)
	{
		printk (KERN_DEBUG "NCSI(%s):(%d.%d.%d) Set Vetobit for NCSI Interface..\n", 
					work->InterfaceName, work->PackageId, work->ChannelId, work->VetoBit);

		netif_carrier_on(info->dev);//make sure we can transmit
		if (Ver3 == 0){ // read VersionID only once 
			/* Get Version ID and verify it is > 1.0  */
			if (NCSI_Issue_GetVersionID(info,work->PackageId,work->ChannelId,&Ver1,&Ver2,&Ver3) != 0)
			{
				printk(KERN_DEBUG "NCSI(%s):%d.%d Get Version IDFailed\n",work->InterfaceName,work->PackageId, work->ChannelId);
				InitEthtoolInfo(info);
				kfree((void *)data);
				Ver3 = 0;
				return;
			}
			printk("Manufacturer ID :: (0x%08lx)\n", Ver3);
		}

		switch (Ver3)
		{
		
		case 0x57010000:	//For Intel Management Controller
			printk(KERN_DEBUG "NCSI(%s):%d.%d %d Set Intel Management Control\n",work->InterfaceName,work->PackageId, work->ChannelId,work->VetoBit);
			// Enable/Disable Keep Phy Link Up feature for Intel GbE Controller
			if (NCSI_Issue_OEM_SetIntelManagementControlCommand(info,work->PackageId, work->ChannelId, work->VetoBit) != 0)
			{
				printk(KERN_DEBUG "NCSI(%s):%d.%d.%d Set Intel Management Control Failed\n",work->InterfaceName,work->PackageId, work->ChannelId, work->VetoBit);
			}
		break;
			
		default:
			printk(">>>>>>>>>NCSI Management Control is not supported<<<<<<<<<<<<\n");
		break;
		}	
		InitEthtoolInfo(info);
	}

	kfree((void *)data);
	
	return;
}

static void 
NCSI_SendUserCommand(struct work_struct *data)
{
	SendUserCommandReq_T *work;
	NCSI_IF_INFO *info;

	if (data == NULL) return;

	work = (SendUserCommandReq_T *)data;
	info = GetInterfaceInfoByName(work->InterfaceName);

	if (info != NULL)
	{
		if (NCSI_Issue_UserCommand(info,work->PackageId, work->ChannelId, work->Command, work->Data, work->Length) != 0)
		{
			printk ("NCSI(%s): %d.%d Send User Command Failed\n", work->InterfaceName, work->PackageId, work->ChannelId);
		}
	}

	kfree((void *)data);
	
	return;
}

static void NCSI_SetFlowControl(struct work_struct *data)
{
	SetFlowcontrolReq_T *work;
	NCSI_IF_INFO *info;

		if (data == NULL) return;
		
		work = (SetFlowcontrolReq_T *)data;
		info = GetInterfaceInfoByName(work->InterfaceName);
		if (info != NULL)
		{
			if (NCSI_Issue_SetNCSIFlowControl(info, work->PackageId, work->Flowcontrol)!=0)
				printk ("NCSI(%s): %d Set Flow Control Command Failed\n", work->InterfaceName, work->PackageId);	
		}
		kfree((void *)data);
		return;
}

int
SendUserCommand(void)
{
	SendUserCommandReq_T *work = (SendUserCommandReq_T *)kmalloc(sizeof(SendUserCommandReq_T), GFP_KERNEL);
	int destLen = 0;

	if (work == NULL)
	{
		printk("NCSI:ERROR: Unable to allocate memory for the work queue item\n");
		return 1;
	}
	
	memset(work, 0, sizeof(SendUserCommandReq_T));

	INIT_WORK((struct work_struct *)work, NCSI_SendUserCommand);

	destLen = sizeof(work->InterfaceName);
	strncpy(work->InterfaceName, UserInterface, destLen);
	if (work->InterfaceName[destLen - 1] != 0) work->InterfaceName[destLen - 1] = 0;
	

	work->PackageId = UserPackageID;
	work->ChannelId = UserChannelID;
	work->Length = UserCommand[1] - 1;

	work->Command = UserCommand[0];
	memcpy (&work->Data[0], &UserCommand[2], sizeof (unsigned int) * (work->Length));
	memset (UserCommand, 0, sizeof(UserCommand));
	
	queue_work(ncsi_wq, (struct work_struct *)work);
	
	return 0;
}

int
SetUserSettings(int ID)
{
	SetUserSettingsReq_T *work = (SetUserSettingsReq_T *)kmalloc(sizeof(SetUserSettingsReq_T), GFP_KERNEL);
	int destLen = 0;

	if (work == NULL)
	{
		printk("NCSI:ERROR: Unable to allocate memory for the work queue item\n");
		return 1;
	}
	
	memset(work, 0, sizeof(SetUserSettingsReq_T));

	INIT_WORK((struct work_struct *)work, NCSI_SetUserSettings);

	destLen = sizeof(work->InterfaceName);
	strncpy(work->InterfaceName, UserInterface, destLen);
	if (work->InterfaceName[destLen - 1] != 0) work->InterfaceName[destLen - 1] = 0;

	work->AutoSelect = UserAuto;
	work->PackageId = UserPackageID;
	work->ChannelId = UserChannelID;
	work->VLANId = ID;
	
	queue_work(ncsi_wq, (struct work_struct *)work);
	
	return 0;
}

int SetReEnable(void)
{
	SetUserSettingsReq_T *work = (SetUserSettingsReq_T *)kmalloc(sizeof(SetUserSettingsReq_T), GFP_KERNEL);
	int destLen = 0;
	
	if (work == NULL)
	{
		printk("NCSI:ERROR: Unable to allocate memory for the work queue item\n");
		return 1;
	}
		
	memset(work, 0, sizeof(SetUserSettingsReq_T));

	INIT_WORK((struct work_struct *)work, NCSI_ReEnable);

	destLen = sizeof(work->InterfaceName);
	strncpy(work->InterfaceName, UserInterface, destLen);
	if (work->InterfaceName[destLen - 1] != 0) work->InterfaceName[destLen - 1] = 0;

	work->AutoSelect = UserAuto;
	work->PackageId = UserPackageID;
	work->ChannelId = UserChannelID;
	work->VLANId = UserVlanID;
		
	queue_work(ncsi_wq, (struct work_struct *)work);
	return 0;
}

int SetMAC(void)
{
	SetUserSettingsReq_T *work = (SetUserSettingsReq_T *)kmalloc(sizeof(SetUserSettingsReq_T), GFP_KERNEL);
	if (work == NULL)
	{
	    printk("NCSI:ERROR: Unable to allocate memory for the work queue item\n");
	    return 1;
	}

	memset(work, 0, sizeof(SetUserSettingsReq_T));
	INIT_WORK((struct work_struct *)work, NCSI_SetMAC);
	queue_work(ncsi_wq, (struct work_struct *)work);

	return 0;
}

int
SetUserLink(void)
{
	SetUserLinkReq_T *work = (SetUserLinkReq_T *)kmalloc(sizeof(SetUserLinkReq_T), GFP_KERNEL);
	int destLen = 0;

	if (work == NULL)
	{
		printk("NCSI:ERROR: Unable to allocate memory for the work queue item\n");
		return 1;
	}
	
	memset(work, 0, sizeof(SetUserLinkReq_T));

	INIT_WORK((struct work_struct *)work, NCSI_SetUserLink);

	destLen = sizeof(work->InterfaceName);
	strncpy(work->InterfaceName, UserInterface, destLen);
	if (work->InterfaceName[destLen - 1] != 0) work->InterfaceName[destLen - 1] = 0;

	work->PackageId = UserPackageID;
	work->ChannelId = UserChannelID;
	work->Speed = UserSpeed;
	work->Duplex = UserDuplex;
	work->AutoNeg = UserAutoNeg;
	
	
	queue_work(ncsi_wq, (struct work_struct *)work);
	
	return 0;
}

#ifdef CONFIG_SPX_FEATURE_NCSI_MANUAL_DETECT
int
SetUserDetect(void)
{
    UserDetectReq_T *work = (UserDetectReq_T *)kmalloc(sizeof(UserDetectReq_T), GFP_KERNEL);
 
    if (work == NULL)
    {
        printk("NCSI:ERROR: Unable to allocate memory for the work queue item\n");
        return 1;
    }
    
    memset(work, 0, sizeof(UserDetectReq_T));
    INIT_WORK((struct work_struct *)work, NCSI_SetUserDetect);
    queue_work(ncsi_wq, (struct work_struct *)work);
    
    return 0;
}
#endif

int
SetUserVetoBit(void)
{
	SetUserVetoBitReq_T *work = (SetUserVetoBitReq_T *)kmalloc(sizeof(SetUserVetoBitReq_T), GFP_KERNEL);
	int destLen = 0;

	if (work == NULL)
	{
		printk("NCSI:ERROR: Unable to allocate memory for the work queue item\n");
		return 1;
	}
	
	memset(work, 0, sizeof(SetUserVetoBitReq_T));

	work->PackageId = UserPackageID;
	work->ChannelId = UserChannelID;

	INIT_WORK((struct work_struct *)work, NCSI_SetUserVetoBit);
	
	destLen = sizeof(work->InterfaceName);
	strncpy(work->InterfaceName, UserInterface, destLen);
	if (work->InterfaceName[destLen - 1] != 0) work->InterfaceName[destLen - 1] = 0;

	work->VetoBit = UserVetoBit;
	
	queue_work(ncsi_wq, (struct work_struct *)work);
	
	return 0;
}

int Setflowcontrol(int Flowcontrol)
{
	SetFlowcontrolReq_T *work = (SetFlowcontrolReq_T *)kmalloc(sizeof(SetFlowcontrolReq_T), GFP_KERNEL);
	int destLen = 0;
	if (work == NULL)
		
	{
		printk("NCSI:ERROR: Unable to allocate memory for the work queue item\n");
		return 1;
	}
	
	
	memset(work, 0, sizeof(SetFlowcontrolReq_T));

	work->PackageId = UserPackageID;
	work->ChannelId = 0x1F;
	
	INIT_WORK((struct work_struct *)work, NCSI_SetFlowControl);
	
	destLen = sizeof(work->InterfaceName);
	strncpy(work->InterfaceName, UserInterface, destLen);
	if (work->InterfaceName[destLen - 1] != 0) work->InterfaceName[destLen - 1] = 0;
		
	work->Flowcontrol = (UINT8)Flowcontrol;
		
	queue_work(ncsi_wq, (struct work_struct *)work);
		
	return 0;
}
