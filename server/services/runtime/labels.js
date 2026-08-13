'use strict';

const Integrity = { TRUSTED: 'trusted', UNTRUSTED: 'untrusted' };
const Confidentiality = { PUBLIC: 'public', PRIVATE: 'private' };

class FlowLabels {
  constructor(integrity = Integrity.TRUSTED, confidentiality = Confidentiality.PUBLIC) {
    this.integrity = integrity;
    this.confidentiality = confidentiality;
  }

  static trustedPublic() {
    return new FlowLabels();
  }

  merge(other) {
    const integrity =
      this.integrity === Integrity.UNTRUSTED || other.integrity === Integrity.UNTRUSTED
        ? Integrity.UNTRUSTED
        : Integrity.TRUSTED;
    const confidentiality =
      this.confidentiality === Confidentiality.PRIVATE ||
      other.confidentiality === Confidentiality.PRIVATE
        ? Confidentiality.PRIVATE
        : Confidentiality.PUBLIC;
    return new FlowLabels(integrity, confidentiality);
  }

  toDict() {
    return { integrity: this.integrity, confidentiality: this.confidentiality };
  }

  static fromDict(data) {
    if (!data) return FlowLabels.trustedPublic();
    const integrity =
      String(data.integrity || 'trusted').toLowerCase() === 'untrusted'
        ? Integrity.UNTRUSTED
        : Integrity.TRUSTED;
    const confidentiality =
      ['private', 'secret', 'confidential', 'pii'].includes(
        String(data.confidentiality || 'public').toLowerCase()
      )
        ? Confidentiality.PRIVATE
        : Confidentiality.PUBLIC;
    return new FlowLabels(integrity, confidentiality);
  }
}

module.exports = { Integrity, Confidentiality, FlowLabels };
