package eidc32proxy

import (
	"fmt"
)

const (
	BufferedEventFlag EventType = 32768         // AND-ed with event value to indicate a buffered (rather than live) event
	EventRequestURI             = "/eidc/event" // sent via POST; body contains a EventRequest
)

const (
	EventDeviceStartup                                 EventType = 1
	EventReflashSuccessful                             EventType = 2
	EventReflashFailed                                 EventType = 3
	EventError                                         EventType = 4
	EventEventBufferOverflow                           EventType = 5
	EventDeviceCommunicationEstablish                  EventType = 6
	EventDeviceCommunicationLost                       EventType = 7
	EventPowerNormal                                   EventType = 8
	EventPowerLost                                     EventType = 9
	EventBatteryNormal                                 EventType = 10
	EventBatteryLost                                   EventType = 11
	EventDownloadSuccess                               EventType = 12
	EventDownloadError                                 EventType = 13
	EventTamperAbnormal                                EventType = 14
	EventTamperNormal                                  EventType = 15
	EventSupervisionAbnormal                           EventType = 16
	EventSupervisionNormal                             EventType = 17
	EventInputBypassed                                 EventType = 33
	EventInputUnBypassed                               EventType = 34
	EventInputInactivityReport                         EventType = 35
	EventOutputOverridden                              EventType = 36
	EventOutputUnOverridden                            EventType = 37
	EventUnrecognizedCardFormat                        EventType = 48
	EventReaderServiceUndefined                        EventType = 49
	EventAuthentication_UnknownCard                    EventType = 50
	EventAuthentication_CardOutdated                   EventType = 51
	EventAuthentication_CardNotYetActive               EventType = 52
	EventAuthentication_CardExpired                    EventType = 53
	EventAuthentication_CardBlocked                    EventType = 54
	EventAuthentication_PINMismatch                    EventType = 55
	EventAuthentication_TooManyRetries                 EventType = 56
	EventAuthentication_GroupNotDefined                EventType = 57
	EventAuthentication_DoubleTap                      EventType = 58
	EventAccessGranted                                 EventType = 64
	EventAccessDenied_InsufficientPrivileges           EventType = 65
	EventAccessDenied_OutOfPrivilegeSchedule           EventType = 66
	EventAccessDenied_ConditionNotMet                  EventType = 67
	EventAccessDenied_PriorityTriggerActive            EventType = 68
	EventAccessDenied_PassbackViolation                EventType = 69
	EventAccessRestricted                              EventType = 70
	EventAccessEvent_PassbackViolation                 EventType = 71
	EventAccessEvent_DoorOpenTooLong                   EventType = 72
	EventAlarm_InAlarm                                 EventType = 80
	EventAlarm_Armed                                   EventType = 81
	EventAlarm_Disarmed                                EventType = 82
	EventAlarm_Restored                                EventType = 83
	EventArming_Armed                                  EventType = 88
	EventArming_ArmFailed_InsufficientPrivileges       EventType = 89
	EventArming_ArmFailed_OutOfPrivilegeSchedule       EventType = 90
	EventArming_ArmFailed_ConditionNotMet              EventType = 91
	EventArming_ArmFailed_PriorityTriggerActive        EventType = 92
	EventArming_Disarmed                               EventType = 93
	EventServiceActivated                              EventType = 96
	EventServiceActivationFailed_ConditionNotMet       EventType = 97
	EventServiceActivationFailed_PriorityTriggerActive EventType = 98
	EventServiceDeactivated                            EventType = 99
	EventElevatorAccessGranted                         EventType = 104
	EventElevatorAccessDenied_InsufficientPrivileges   EventType = 105
	EventElevatorAccessDenied_OutOfPrivilegeSchedule   EventType = 106
	EventElevatorAccessDenied_ConditionNotMet          EventType = 107
	EventElevatorAccessDenied_PriorityTriggerActive    EventType = 108
	EventElevatorAccessRestricted                      EventType = 109
	EventLOW_VOLTAGE                                   EventType = 117
	EventVOLTAGE_NORMAL                                EventType = 118
	EventDC1_POWER_TROUBLE                             EventType = 122
	EventDC2_POWER_TROUBLE                             EventType = 123
	EventDC1_POWER_RESTORED                            EventType = 124
	EventDC2_POWER_RESTORED                            EventType = 125
	EventReboot                                        EventType = 128
	EventStarted                                       EventType = 129
	EventSetNetworkInfo                                EventType = 130
	EventReflashFirmware                               EventType = 131
	EventCONNECTION_START                              EventType = 144
	EventCONNECTION_START_DNS                          EventType = 145
	EventCONNECTION_HAVE_IP                            EventType = 146
	EventCONNECTION_CONNECTED                          EventType = 147
	EventCONNECTION_DISCONNECTED                       EventType = 148
	EventCONNECTION_FAILED                             EventType = 149
	EventCONNECTION_START_SSL                          EventType = 150
	EventCONNECTION_NO_DNS_SERVER                      EventType = 151
)

type EventType uint16

func (o EventType) String() string {
	// strip the buffered flag
	evtType := o & ^BufferedEventFlag
	var result string
	switch evtType {
	case 1:
		result = "DeviceStartup"
	case 2:
		result = "ReflashSuccessful"
	case 3:
		result = "ReflashFailed"
	case 4:
		result = "Error"
	case 5:
		result = "EventBufferOverflow"
	case 6:
		result = "DeviceCommunicationEstablish"
	case 7:
		result = "DeviceCommunicationLost"
	case 8:
		result = "PowerNormal"
	case 9:
		result = "PowerLost"
	case 10:
		result = "BatteryNormal"
	case 11:
		result = "BatteryLost"
	case 12:
		result = "DownloadSuccess"
	case 13:
		result = "DownloadError"
	case 14:
		result = "TamperAbnormal"
	case 15:
		result = "TamperNormal"
	case 16:
		result = "SupervisionAbnormal"
	case 17:
		result = "SupervisionNormal"
	case 33:
		result = "InputBypassed"
	case 34:
		result = "InputUnBypassed"
	case 35:
		result = "InputInactivityReport"
	case 36:
		result = "OutputOverridden"
	case 37:
		result = "OutputUnOverridden"
	case 48:
		result = "UnrecognizedCardFormat"
	case 49:
		result = "ReaderServiceUndefined"
	case 50:
		result = "Authentication_UnknownCard"
	case 51:
		result = "Authentication_CardOutdated"
	case 52:
		result = "Authentication_CardNotYetActive"
	case 53:
		result = "Authentication_CardExpired"
	case 54:
		result = "Authentication_CardBlocked"
	case 55:
		result = "Authentication_PINMismatch"
	case 56:
		result = "Authentication_TooManyRetries"
	case 57:
		result = "Authentication_GroupNotDefined"
	case 58:
		result = "Authentication_DoubleTap"
	case 64:
		result = "AccessGranted"
	case 65:
		result = "AccessDenied_InsufficientPrivileges"
	case 66:
		result = "AccessDenied_OutOfPrivilegeSchedule"
	case 67:
		result = "AccessDenied_ConditionNotMet"
	case 68:
		result = "AccessDenied_PriorityTriggerActive"
	case 69:
		result = "AccessDenied_PassbackViolation"
	case 70:
		result = "AccessRestricted"
	case 71:
		result = "AccessEvent_PassbackViolation"
	case 72:
		result = "AccessEvent_DoorOpenTooLong"
	case 80:
		result = "Alarm_InAlarm"
	case 81:
		result = "Alarm_Armed"
	case 82:
		result = "Alarm_Disarmed"
	case 83:
		result = "Alarm_Restored"
	case 88:
		result = "Arming_Armed"
	case 89:
		result = "Arming_ArmFailed_InsufficientPrivileges"
	case 90:
		result = "Arming_ArmFailed_OutOfPrivilegeSchedule"
	case 91:
		result = "Arming_ArmFailed_ConditionNotMet"
	case 92:
		result = "Arming_ArmFailed_PriorityTriggerActive"
	case 93:
		result = "Arming_Disarmed"
	case 96:
		result = "ServiceActivated"
	case 97:
		result = "ServiceActivationFailed_ConditionNotMet"
	case 98:
		result = "ServiceActivationFailed_PriorityTriggerActive"
	case 99:
		result = "ServiceDeactivated"
	case 104:
		result = "ElevatorAccessGranted"
	case 105:
		result = "ElevatorAccessDenied_InsufficientPrivileges"
	case 106:
		result = "ElevatorAccessDenied_OutOfPrivilegeSchedule"
	case 107:
		result = "ElevatorAccessDenied_ConditionNotMet"
	case 108:
		result = "ElevatorAccessDenied_PriorityTriggerActive"
	case 109:
		result = "ElevatorAccessRestricted"
	case 117:
		result = "LOW_VOLTAGE"
	case 118:
		result = "VOLTAGE_NORMAL"
	case 122:
		result = "DC1_POWER_TROUBLE"
	case 123:
		result = "DC2_POWER_TROUBLE"
	case 124:
		result = "DC1_POWER_RESTORED"
	case 125:
		result = "DC2_POWER_RESTORED"
	case 128:
		result = "Reboot"
	case 129:
		result = "Started"
	case 130:
		result = "SetNetworkInfo"
	case 131:
		result = "ReflashFirmware"
	case 144:
		result = "CONNECTION_START"
	case 145:
		result = "CONNECTION_START_DNS"
	case 146:
		result = "CONNECTION_HAVE_IP"
	case 147:
		result = "CONNECTION_CONNECTED"
	case 148:
		result = "CONNECTION_DISCONNECTED"
	case 149:
		result = "CONNECTION_FAILED"
	case 150:
		result = "CONNECTION_START_SSL"
	case 151:
		result = "CONNECTION_NO_DNS_SERVER"
	default:
		result = "Unknown_Event_Type"
	}
	buffered := o&BufferedEventFlag == BufferedEventFlag
	if buffered {
		result = fmt.Sprintf("(%s)", result)
	}
	return result
}
