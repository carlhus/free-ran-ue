package ue

import "github.com/free5gc/nas/ie"

// NasObserver receives the PDU session events of a UE, so the embedding process can act on them.
// Except for DataPlaneError, the callbacks run on the goroutine that reads downlink NAS,
// so they should return promptly and must not wait for further downlink NAS.
type NasObserver interface {
	// PduSessionEstablishmentAccepted delivers the operator containers of the Establishment Accept ePCO.
	PduSessionEstablishmentAccepted(operatorContainers []ie.OperatorContainer)
	// PduSessionModificationCommand delivers the operator containers of a Modification Command,
	// and the reply decides whether the UE answers with Complete or Command Reject.
	PduSessionModificationCommand(pti uint8, operatorContainers []ie.OperatorContainer) ModificationCommandReply
	// PduSessionModificationRejected delivers a Modification Reject of the request with that PTI.
	PduSessionModificationRejected(pti uint8, cause uint8, operatorContainers []ie.OperatorContainer)
	// PduSessionReleased reports a network-initiated PDU Session Release, which the UE has completed.
	PduSessionReleased(cause uint8)
	// UeContextReleased reports that the gNB closed the control connection, which it does
	// when it releases the UE context, and also when the gNB itself stops.
	UeContextReleased()
	// DataPlaneError reports an error on the RAN data plane socket.
	DataPlaneError(err error)
}

// ModificationCommandReply is how the UE answers a PDU Session Modification Command:
// with Modification Complete, or with Modification Command Reject carrying Cause when Reject is set.
type ModificationCommandReply struct {
	Reject bool
	Cause  uint8
}

// nopNasObserver completes every Modification Command and ignores the other events.
type nopNasObserver struct{}

func (nopNasObserver) PduSessionEstablishmentAccepted([]ie.OperatorContainer) {}

func (nopNasObserver) PduSessionModificationCommand(uint8, []ie.OperatorContainer) ModificationCommandReply {
	return ModificationCommandReply{}
}

func (nopNasObserver) PduSessionModificationRejected(uint8, uint8, []ie.OperatorContainer) {}

func (nopNasObserver) PduSessionReleased(uint8) {}

func (nopNasObserver) UeContextReleased() {}

func (nopNasObserver) DataPlaneError(error) {}
