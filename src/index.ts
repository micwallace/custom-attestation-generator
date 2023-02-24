import {hexStringToUint8, uint8tohex} from "@tokenscript/attestation/dist/libs/utils";
import {SchemaGenerator} from "./SchemaGenerator";
import {AsnSerializer} from "@peculiar/asn1-schema";
import {KeyPair} from "@tokenscript/attestation/dist/libs/KeyPair";
import {ethers} from "ethers";
import QRCode from 'qrcode';

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

		window.agen.renderQr()

	} catch (e){
		console.error(e);
		alert(e.message);
	}

}

interface ISchemaFieldConfig {
	[name: string]: { type: string, optional: boolean }
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
			fieldValues[name] = convertFieldValue(field.type, value);
		}
	}

	let validity: null|{from: number, to: number} = null;

	if (validityEnable.checked){
		const from = Math.round(validityFrom.valueAsNumber / 1000);
		const to = Math.round(validityTo.valueAsNumber / 1000);

		validity = {from, to};
	}

	return {schemaFields, fieldValues, validity};
}

function convertFieldValue(type: string, value: any){

	switch (type) {
		case ASN_FIELD_TYPES.Integer:
			value = parseInt(value);
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

window.agen.addField = () => {

	const row = document.createElement("tr");

	row.innerHTML = `
		<td>
			<label>Name
				<input class="field-name" type="text"/>
			</label>
		</td>
		<td>
		  <label>Type
			  <select class="field-type">
				  ${Object.keys(ASN_FIELD_TYPES)
					.map((type:string, index) => `<option value="${type}" ${index === 0 ? "selected" : ""}>${type}</option>`).join("\n")}
			  </select>
		  </label>
		</td>
		<td>
		  <label>Optional
			<input class="field-optional" type="checkbox"/>
		  </label>
		</td>
		<td>
		  <label>Value
			  <input class="field-value" type="text"/>
		  </label>
		</td>
		<td>
			<button type="button" onclick="agen.removeField(this)">X</button>
		</td>
	`;

	schemaTable.append(row);
}

window.agen.removeField = (elem: Element) => {
	elem.parentElement.parentElement.remove();
}

window.agen.validityToggle = (elem: HTMLInputElement) => {

	if (elem.checked){
		validityFrom.valueAsNumber = Date.now();
		validityFrom.removeAttribute("disabled");
		validityTo.valueAsNumber = Date.now() + 86400000;
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

class CustomAttestationGenerator {

	constructor(private customFields: ISchemaFieldConfig, private attestorKeys: KeyPair, private hasValidity = false) {

	}

	public generateAndSignAttestation(fieldValues: {[name: string]: any}, validity?: {from: number, to: number}){

		const generatedSchema = this.generateAttestationSchema();

		let attestation = this.createAttestationFromSchema(generatedSchema, fieldValues, validity);

		attestation = this.signAttestation(attestation);

		console.log("Generated attestation: ", attestation);

		let encoded = generatedSchema.serializeAndFormat(attestation);

		console.log("Encoded: ", encoded);

		this.verifyAttestation(encoded);

		return encoded;
	}

	public verifyAttestation(hexAttestation: string){

		const generatedSchema = this.generateAttestationSchema();

		let decoded = generatedSchema.parse(hexAttestation);

		console.log("Decoded: ");
		console.log(decoded);

		const encAttestation = AsnSerializer.serialize(decoded.ticket);

		let payloadHash = hexStringToUint8(ethers.utils.keccak256(new Uint8Array(encAttestation)));

		// TODO: Optionally use address like smart contract validation
		//let address = ethers.utils.recoverAddress(payloadHash, ethers.utils.splitSignature(new Uint8Array(this.linkedAttestation.signatureValue)));

		let pubKey = ethers.utils.recoverPublicKey(payloadHash, ethers.utils.splitSignature(new Uint8Array(decoded.signatureValue)));

		if (pubKey.substring(2) !== this.attestorKeys.getPublicKeyAsHexStr())
			throw new Error("Attestor public key does not match, expected " + this.attestorKeys.getPublicKeyAsHexStr() + " got " + pubKey.substring(2));

		console.log("Signature successfully verified");

		if (decoded.ticket.validity) {
			let now = Math.round(new Date().getTime() / 1000);

			if (decoded.ticket.validity.notBefore > now)
				throw new Error("Attestation is not yet valid");

			if (decoded.ticket.validity.notAfter < now)
				throw new Error("Attestation has expired");

			console.log("Ticket validity verified");
		}
	}

	public createAttestationFromSchema(schema: SchemaGenerator, fields: {[key: string]: any}, validity?: {from: number, to: number}){

		let asnObject = schema.getSchemaObject();

		for (let i in fields){
			asnObject.ticket[i] = fields[i];
		}

		if (validity){
			asnObject.ticket.validity.notBefore = validity.from;
			asnObject.ticket.validity.notAfter = validity.to;
		}

		console.log("Created attest", asnObject);

		return asnObject;
	}

	public signAttestation(attestation: any){

		const encodedAttest = AsnSerializer.serialize(attestation.ticket);

		// TODO: Add signing algorithm
		//this.linkedAttestation.signingAlgorithm = new AlgorithmIdentifierASN();
		//this.linkedAttestation.signingAlgorithm.algorithm = "1.2.840.10045.4.2"; // Our own internal identifier for ECDSA with keccak256

		attestation.signatureValue = hexStringToUint8(this.attestorKeys.signRawBytesWithEthereum(Array.from(new Uint8Array(encodedAttest))));

		return attestation;
	}

	public generateAttestationSchema(){
		return new SchemaGenerator(this.getSchemaDefinition());
	}

	public getSchemaDefinition(){

		const inbuiltFields: any = {};

		if (this.hasValidity){
			console.log("Schema created with validity");

			inbuiltFields.validity = {
				name: "Validity",
				items: {
					notBefore: {
						type: "Integer",
						optional: false
					},
					notAfter: {
						type: "Integer",
						optional: false
					}
				}
			}
		}

		const schema: any = {
			ticket: {
				name: "Ticket",
				items: {
					...this.customFields,
					...inbuiltFields
				}
			},
			signatureValue: {
				type: "BitString",
				optional: false
			}
		}

		return schema;
	}

}