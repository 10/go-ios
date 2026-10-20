package hid

func buildSendReportPayload(serviceID uint64, report []byte) map[string]interface{} {
	return map[string]interface{}{
		"featureIdentifier": universalFeatureIdentifier,
		"messageType":       "Request",
		"payload": map[string]interface{}{
			"send": map[string]interface{}{
				"_0": report,
				"_1": serviceID,
			},
		},
	}
}

// The device decodes the codable property storage Swift-style, every value
// tagged with its type.
func buildCreateKeyboardPayload() map[string]interface{} {
	usage, page := int64(6), int64(1) // Generic Desktop, Keyboard
	properties := map[string]interface{}{
		"Manufacturer":     map[string]interface{}{"string": "Apple Inc."},
		"Product":          map[string]interface{}{"string": "Keyboard"},
		"ProductID":        map[string]interface{}{"int": int64(0x0250)},
		"VendorID":         map[string]interface{}{"int": int64(0x05AC)},
		"PrimaryUsage":     map[string]interface{}{"int": usage},
		"PrimaryUsagePage": map[string]interface{}{"int": page},
		"DeviceUsagePairs": map[string]interface{}{"array": []interface{}{map[string]interface{}{"dictionary": map[string]interface{}{
			"DeviceUsage":     map[string]interface{}{"int": usage},
			"DeviceUsagePage": map[string]interface{}{"int": page},
		}}}},
		"Transport":                      map[string]interface{}{"string": "USB"},
		"ReportDescriptor":               map[string]interface{}{"data": keyboardDescriptor},
		"UniversalControlVirtualService": map[string]interface{}{"bool": true},
		"_ServiceID":                     map[string]interface{}{"uint": keyboardID},
	}
	service := map[string]interface{}{
		"DeviceUsagePairs":                   []interface{}{map[string]interface{}{"DeviceUsage": usage, "DeviceUsagePage": page}},
		"PrimaryUsage":                       uint64(usage),
		"PrimaryUsagePage":                   uint64(page),
		"Product":                            "Keyboard",
		"ProductID":                          int64(0x0250),
		"VendorID":                           int64(0x05AC),
		"_CoreDevice_codablePropertyStorage": properties,
		"_ServiceID":                         keyboardID,
	}
	return map[string]interface{}{
		"featureIdentifier": universalFeatureIdentifier,
		"messageType":       "Request",
		"payload":           map[string]interface{}{"createService": map[string]interface{}{"_0": service}},
	}
}

func buildButtonPayload(state, usagePage, usage uint64) map[string]interface{} {
	return map[string]interface{}{
		"featureIdentifier": buttonFeatureIdentifier,
		"messageType":       "IndigoButtonEvent",
		"payload":           map[string]interface{}{"state": state, "usagePage": usagePage, "usageCode": usage},
	}
}
