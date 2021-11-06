const VircleLib = require('vircle-lib');
import { IDeriver } from '..';
export abstract class AbstractVircleLibDeriver implements IDeriver {
  public abstract vircleLib;

  deriveAddress(network, pubKey, addressIndex, isChange) {
    const xpub = new this.vircleLib.HDPublicKey(pubKey, network);
    const changeNum = isChange ? 1 : 0;
    const path = `m/${changeNum}/${addressIndex}`;
    return this.vircleLib.Address(xpub.derive(path).publicKey, network).toString();
  }

  derivePrivateKey(network, xPriv, addressIndex, isChange) {
    const xpriv = new this.vircleLib.HDPrivateKey(xPriv, network);
    const changeNum = isChange ? 1 : 0;
    const path = `m/${changeNum}/${addressIndex}`;
    const privKey = xpriv.derive(path).privateKey;
    const pubKey = privKey.publicKey;
    const address = this.vircleLib.Address(pubKey, network).toString();
    return { address, privKey: privKey.toString(), pubKey: pubKey.toString() };
  }
}
export class VclDeriver extends AbstractVircleLibDeriver {
  vircleLib = VircleLib;
}
