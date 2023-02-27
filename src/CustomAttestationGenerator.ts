import {KeyPair} from "@tokenscript/attestation/dist/libs/KeyPair";
import {AsnSerializer} from "@peculiar/asn1-schema";
import {hexStringToUint8} from "@tokenscript/attestation/dist/libs/utils";
import {ethers} from "ethers";
import {SchemaGenerator} from "./SchemaGenerator";

export interface ISchemaFieldConfig {
	[name: string]: { type: string, optional: boolean }
}

export class CustomAttestationGenerator {

	constructor(private customFields: ISchemaFieldConfig, private attestorKeys: KeyPair, private hasValidity = false) {

	}

	public generateAndSignAttestation(fieldValues: {[name: string]: any}, validity?: {from: number, to: number}){

		const generatedSchema = this.generateAttestationSchema();

		let attestation = this.createAttestationFromSchema(generatedSchema, fieldValues, validity);

		attestation = this.signAttestation(attestation);

		console.log("Generated attestation: ", attestation);

		let encoded = generatedSchema.serializeAndFormat(attestation);

		console.log("Encoded: ", encoded);

		this.verifyAttestation(encoded, true);

		return encoded;
	}

	public verifyAttestation(hexAttestation: string, warnValidityOnly = false){

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

			if (decoded.ticket.validity.notBefore > now) {
				const msg = "Attestation is not yet valid";
				if (warnValidityOnly) alert("Warning: " + msg); else throw new Error(msg);
			}

			if (decoded.ticket.validity.notAfter < now) {
				const msg = "Attestation has expired";
				if (warnValidityOnly) alert("Warning: " + msg); else throw new Error(msg);
			}

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