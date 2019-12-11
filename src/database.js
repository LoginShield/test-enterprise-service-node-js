const { Collection } = require('./database-collection');

class Database {
    constructor(storage = {}) {
        this.storage = storage;
    }

    collection(name) {
        if (typeof this.storage[name] !== 'object') {
            this.storage[name] = {};
        }
        return new Collection(name, this.storage[name]);
    }
}

module.exports = { Database };
