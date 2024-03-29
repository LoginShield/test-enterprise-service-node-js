class Collection {
    constructor(name, storage = {}) {
        this.name = name;
        this.storage = storage;
    }

    async insert(id, content) {
        if (this.storage[id]) {
            console.log(`collection ${this.name}: insert failed for id: ${id}`);
            return false;
        }
        this.storage[id] = content;
        console.log(`collection ${this.name}: insert id ${id} content: ${JSON.stringify(content)}`);
        return true;
    }

    async editById(id, content) {
        const existing = this.storage[id];
        if (typeof existing === 'string' && typeof content === 'string') {
            this.storage[id] = content;
            console.log(`collection ${this.name}: edit id ${id} content: ${JSON.stringify(content)}`);
            return true;
        }
        if (typeof existing === 'object' && typeof content === 'object') {
            this.storage[id] = { ...existing, ...content };
            console.log(`collection ${this.name}: edit id ${id} content: ${JSON.stringify(content)}`);
            return true;
        }
        console.log(`collection ${this.name}: edit failed for id: ${id}`);
        return false;
    }

    async fetchById(id) {
        if (typeof this.storage[id] === 'object' || typeof this.storage[id] === 'string') {
            console.log(`collection ${this.name}: fetch id ${id} content: ${JSON.stringify(this.storage[id])}`);
            return this.storage[id];
        }
        console.log(`collection ${this.name}: fetch failed for id: ${id}`);
        return null;
    }

    async deleteById(id) {
        if (this.storage[id]) {
            console.log(`collection ${this.name}: delete id ${id} content: ${JSON.stringify(this.storage[id])}`);
            delete this.storage[id];
            return true;
        }
        console.log(`collection ${this.name}: delete failed for id: ${id}`);
        return false;
    }
}

module.exports = { Collection };
