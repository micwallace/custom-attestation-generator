import {hexStringToUint8} from "@tokenscript/attestation/dist/libs/utils";
import {KeyPair} from "@tokenscript/attestation/dist/libs/KeyPair";
import QRCode from 'qrcode';
import {CustomAttestationGenerator, ISchemaFieldConfig} from "./CustomAttestationGenerator";

declare global {
	interface Window {
		agen: any
	}
}

window.agen = {};

const schemaTable = document.querySelector("#schema-table tbody");
const privKeyInput = document.querySelector("#priv-key") as HTMLTextAreaElement;
const schemaOutput = document.querySelector("#output-schema") as HTMLTextAreaElement;
const attestationOutput = document.querySelector("#output-attestation") as HTMLTextAreaElement;

const validityEnable = document.querySelector("#validity-enable") as HTMLInputElement;
const validityFrom = document.querySelector("#validity-from") as HTMLInputElement;
const validityTo = document.querySelector("#validity-to") as HTMLInputElement;

const qrCanvas = document.querySelector("#qr-canvas") as HTMLCanvasElement;
const qrDecimal = document.querySelector("#qr-decimal") as HTMLSpanElement;
const chainInput = document.querySelector("#qr-chain") as HTMLInputElement;
const addressInput = document.querySelector("#qr-address") as HTMLInputElement;

const ASN_FIELD_TYPES = {
	Integer: "Integer",
	Utf8String: "Utf8String",
	Boolean: "Boolean",
	OctetString: "OctetString",
	BitString: "BitString"
}

window.agen.testGenSchema = () => {

	const ATTESTOR_PRIV_KEY = "7411181bdb51a24edd197bacda369830b1c89bbf872a4c2babbdd2e94f25d3b5";
	const attestorKeys = KeyPair.fromPrivateUint8(hexStringToUint8(ATTESTOR_PRIV_KEY), 'secp256k1');

	const attGen = new CustomAttestationGenerator({
		devconId: {
			type: "Utf8String",
			optional: false
		},
		ticketIdNumber: {
			type: "Integer",
			optional: true
		},
		ticketIdString: {
			type: "Utf8String",
			optional: true
		},
		ticketClass: {
			type: "Integer",
			optional: false
		}
	}, attestorKeys);

	const hexAttest = attGen.generateAndSignAttestation({
		devconId: "6",
		ticketIdNumber: 5,
		ticketClass: 1
	});
}

window.agen.renderQr = () => {

	renderQr();

	if (!document.location.hash.length)
		return;

	const query = new URLSearchParams(document.location.hash.substring(1));

	query.set("address", addressInput.value);
	query.set("chain", chainInput.value);

	document.location.hash = query.toString();
}

function renderQr(){
	const attestation = "0x" + attestationOutput.value;
	const chainId = chainInput.value;
	const contractAddress = addressInput.value;

	const decimalAddr: string = BigInt(contractAddress).toString(10);
	const qrString = chainId.length + chainId + decimalAddr.padStart(49, "0") + BigInt(attestation).toString(10);

	QRCode.toCanvas(qrCanvas, qrString, function (error) {
		if (error) console.error(error)
	})

	qrDecimal.innerHTML = qrString;
}

window.agen.generateAttestation = () => {

	try {

		const attestorKeys = getKeyPair();

		const {schemaFields, fieldValues, validity} = validateAndGetValues();

		const schema = new CustomAttestationGenerator(schemaFields, attestorKeys, !!validity);

		const hexAttest = schema.generateAndSignAttestation(fieldValues, validity);

		schemaOutput.value = JSON.stringify(schema.getSchemaDefinition(), null, 2);
		attestationOutput.value = hexAttest;

		renderQr()

		updateURLHash(schemaFields, fieldValues, validity);

	} catch (e){
		console.error(e);
		alert(e.message);
	}

}

function getKeyPair(){

	if (!privKeyInput.value)
		throw new Error("Please input private key or refresh the page to use a test key");

	return KeyPair.fromPrivateUint8(hexStringToUint8(privKeyInput.value), 'secp256k1');
}

function validateAndGetValues(){

	const schemaFields: ISchemaFieldConfig = {};
	const fieldValues: {[name: string]: any} = {};

	const rows = schemaTable.querySelectorAll("tbody tr")

	for (let row of rows){

		const name = (row.querySelector(".field-name") as HTMLInputElement).value;

		if (!name)
			throw new Error("Name must be entered.");

		if (schemaFields[name])
			throw new Error("Duplicate field name, all names must be unique.");

		const field = {
			type: (row.querySelector('.field-type') as HTMLSelectElement).value,
			optional: (row.querySelector('.field-optional') as HTMLInputElement).checked
		}

		let value: any = (row.querySelector(".field-value") as HTMLInputElement).value;

		if (!field.optional && !value)
			throw new Error("Non-optional fields must have a value");

		schemaFields[name] = field;

		if (value) {
			fieldValues[name] = convertFieldValue(field.type, name, value);
		}
	}

	let validity: null|{from: number, to: number} = null;

	if (validityEnable.checked){
		let userTimezoneOffset = new Date().getTimezoneOffset() * 60000;

		const from = Math.round((validityFrom.valueAsNumber + userTimezoneOffset) / 1000);
		const to = Math.round((validityTo.valueAsNumber + userTimezoneOffset) / 1000);

		validity = {from, to};
	}

	return {schemaFields, fieldValues, validity};
}

function convertFieldValue(type: string, name: string, value: any){

	switch (type) {
		case ASN_FIELD_TYPES.Integer:
			value = parseInt(value);
			if (isNaN(value))
				throw new Error("Field value for '" + name + "' is not a valid number, please change the field type or value to match");
			break;
		case ASN_FIELD_TYPES.Boolean:
			value = Boolean(value);
			break;
		case ASN_FIELD_TYPES.BitString:
		case ASN_FIELD_TYPES.OctetString:
			value = hexStringToUint8(value);
			break;
	}

	return value;
}

window.agen.validateAttestation = () => {

	const fields = JSON.parse(schemaOutput.value);
	const attestation = attestationOutput.value;

	try {
		if (!fields || !fields.ticket?.items || !attestation)
			throw new Error("Schema and attestation hex must be provided");

		const keyPair = getKeyPair()

		const useValidity = !!fields.ticket.items.validity;
		delete fields.ticket.items.validity;

		const schema = new CustomAttestationGenerator(fields.ticket.items, keyPair, useValidity);

		schema.verifyAttestation(attestation);

		alert("Attestation successfully validated!");

	} catch (e){
		console.error(e);
		alert(e.message);
	}
}

window.agen.addField = (name?: string, fieldType?: string, optional?: boolean, value?: any) => {

	const row = document.createElement("tr");

	row.innerHTML = `
		<td>
			<label>Name
				<input class="field-name" type="text" value="${name !== undefined ? name : ''}"/>
			</label>
		</td>
		<td>
		  <label>Type
			  <select class="field-type">
				  ${Object.keys(ASN_FIELD_TYPES)
					.map((type:string, index) => `<option value="${type}" ${fieldType === type || (!fieldType && index === 0) ? "selected" : ""}>${type}</option>`).join("\n")}
			  </select>
		  </label>
		</td>
		<td>
		  <label>Optional
			<input class="field-optional" type="checkbox" ${optional === true ? 'checked' : ''}/>
		  </label>
		</td>
		<td>
		  <label>Value
			  <input class="field-value" type="text" value="${value !== undefined ? value : ''}"/>
			  <button type="button" onclick="agen.formatHex(this)" title="Format hex string">0x</button>
		  </label>
		</td>
		<td>
			<button type="button" onclick="agen.removeField(this)" title="Remove row">X</button>
		</td>
	`;

	schemaTable.append(row);
}

window.agen.removeField = (elem: Element) => {
	elem.parentElement.parentElement.remove();
}

window.agen.formatHex = (elem: Element) => {
	const str = elem.parentElement.parentElement.querySelector(".field-value") as HTMLInputElement;

	let val = str.value.toUpperCase();

	if (val.indexOf("0X") === 0)
		val = val.substring(2);

	str.value = val;
}

window.agen.validityToggle = (elem: HTMLInputElement) => {

	if (elem.checked){
		const now = new Date();
		let userTimezoneOffset = now.getTimezoneOffset() * 60000;
		userTimezoneOffset *= Math.sign(userTimezoneOffset);

		validityFrom.valueAsNumber = new Date(now.getTime() + userTimezoneOffset).getTime();
		validityFrom.removeAttribute("disabled");
		validityTo.valueAsNumber = new Date((now.getTime() + userTimezoneOffset) + 86400000).getTime();
		validityTo.removeAttribute("disabled");
	} else {
		validityFrom.value = "";
		validityFrom.setAttribute("disabled", "true");
		validityTo.value = "";
		validityTo.setAttribute("disabled", "true");
	}
}

window.agen.validityToggle(validityEnable); // Perform on load

window.agen.viewInAsnDecoder = () => {

	const attestation = attestationOutput.value;

	if (!attestation)
		return alert("Please enter or generate an attestation first");

	window.open("https://lapo.it/asn1js/#" + attestation, "_blank");
}

function handleUrlLoad(){

	if (document.location.hash.length > 1){

		const query = new URLSearchParams(document.location.hash.substring(1));

		const fields = query.getAll("field");

		if (fields.length) {
			for (let field of fields){
				const [name, type, optional, value] = field.split("-");
				window.agen.addField(name, type, optional === "true", value);
			}
		} else {
			addDefaultFields();
		}

		let userTimezoneOffset = new Date().getTimezoneOffset() * 60000;
		userTimezoneOffset *= Math.sign(userTimezoneOffset);

		if (query.has("validFrom") || query.has("validTo")){
			if (query.has("validFrom"))
				validityFrom.valueAsNumber = new Date((parseInt(query.get("validFrom")) * 1000) + userTimezoneOffset).getTime();

			if (query.has("validTo"))
				validityTo.valueAsNumber = new Date((parseInt(query.get("validTo")) * 1000) + userTimezoneOffset).getTime();
		} else {
			validityEnable.checked = false;
			window.agen.validityToggle(validityEnable);
		}

		if (query.has("address"))
			addressInput.value = query.get("address");

		if (query.has("chain"))
			chainInput.value = query.get("chain");

		window.agen.generateAttestation();
	} else {
		addDefaultFields();
	}
}

function addDefaultFields(){
	// Load default fields
	window.agen.addField("devconId", "UTF8String", false, "6");
	window.agen.addField("ticketIdNumber", "Integer", false, 5);
	window.agen.addField("ticketClass", "Integer", false, 1);
}

document.addEventListener("DOMContentLoaded", handleUrlLoad);

window.agen.testUpdateUrlHash = () => {

	const {schemaFields, fieldValues, validity} = validateAndGetValues();

	updateURLHash(schemaFields, fieldValues, validity);
}

function updateURLHash(schemaFields: ISchemaFieldConfig, fieldValues: {[name: string]: any}, validity?: {from: number, to: number}){

	const query = new URLSearchParams();

	for (let fieldName in schemaFields){
		const config = schemaFields[fieldName];
		query.append("field", `${fieldName}-${config.type}-${config.optional}-${fieldValues[fieldName]}`);
	}

	if (validity) {
		query.set("validFrom", validity.from.toString());
		query.set("validTo", validity.to.toString());
	}

	query.set("address", addressInput.value);
	query.set("chain", chainInput.value);

	document.location.hash = query.toString();
}