package mcinstall

import (
	"io"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/golog"
)

// Erase tells a device to remove all apps and settings. You need to activate it afterwards.
// Be careful with this if you do not have a backup!
func Erase(device ios.DeviceEntry) error {
	conn, err := New(device)
	if err != nil {
		return err
	}
	defer conn.Close()
	golog.Info("start erasing", "module", logModule, "udid", device.Properties.SerialNumber)
	golog.Debug("send flush request", "module", logModule, "udid", device.Properties.SerialNumber)
	if err := conn.Flush(); err != nil {
		return err
	}
	golog.Debug("get cloud config", "module", logModule, "udid", device.Properties.SerialNumber)
	config, err := conn.GetCloudConfiguration()
	if err != nil {
		return err
	}
	golog.Debug("got cloud config", "module", logModule, "udid", device.Properties.SerialNumber, "config", config)

	golog.Debug("send erase request", "module", logModule, "udid", device.Properties.SerialNumber)
	eraseRequest := map[string]interface{}{
		"RequestType":      "EraseDevice",
		"PreserveDataPlan": 1,
	}
	_, err = conn.sendChecked(eraseRequest)
	if err != nil && err != io.EOF {
		return err
	}
	golog.Info("device should be rebooting now", "module", logModule, "udid", device.Properties.SerialNumber)
	return nil
}
