import { IValidation } from '..';
const Vircle = require('vircle-lib');

export class VclValidation implements IValidation {
  validateAddress(network: string, address: string): boolean {
    const Address = Vircle.Address;
    // Regular Address: try Vircle
    return Address.isValid(address, network);
  }

  validateUri(addressUri: string): boolean {
    // Check if the input is a valid uri or address
    const URI = Vircle.URI;
    // Bip21 uri
    return URI.isValid(addressUri);
  }
}
