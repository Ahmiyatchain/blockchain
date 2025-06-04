#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

// --- MediaSubmission structure ---
struct MediaSubmission {
    std::string userPublicKey;
    std::string mediaHash;
    std::string mediaType; // meme/image/video/text

    std::string toString() const {
        std::stringstream ss;
        ss << userPublicKey << "|" << mediaHash << "|" << mediaType;
        return ss.str();
    }
};

// --- Helper function: SHA-256 Hash ---
std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Ctx;
    SHA256_Init(&sha256Ctx);
    SHA256_Update(&sha256Ctx, data.c_str(), data.size());
    SHA256_Final(hash, &sha256Ctx);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

// --- Block structure ---
struct Block {
    int index;
    std::string timestamp;
    std::vector<MediaSubmission> submissions;
    std::string previousHash;
    std::string hash;
    uint64_t nonce;

    Block(int idx, std::vector<MediaSubmission> subs, const std::string& prevHash)
        : index(idx), submissions(subs), previousHash(prevHash), nonce(0) 
    {
        // Set timestamp
        std::time_t now = std::time(nullptr);
        timestamp = std::to_string(now);
        hash = calculateHash();
    }

    std::string calculateHash() const {
        std::stringstream ss;
        ss << index << timestamp;
        for (const auto& m : submissions)
            ss << m.toString();
        ss << previousHash << nonce;
        return sha256(ss.str());
    }
};

// --- Simple Proof-of-Memory (toy version) ---
// Simulate memory usage by requiring allocation of a buffer filled with data
bool proofOfMemory(uint64_t requiredMB = 10) {
    try {
        size_t bytes = requiredMB * 1024 * 1024;
        std::vector<char> buffer(bytes, 'X');
        // Do a quick checksum to make sure memory is "used"
        uint64_t checksum = 0;
        for (size_t i = 0; i < buffer.size(); i += 4096) {
            checksum += buffer[i];
        }
        return (checksum > 0);
    } catch (...) {
        return false;
    }
}

// --- Blockchain container ---
class Blockchain {
public:
    Blockchain() {
        // Genesis block
        std::vector<MediaSubmission> genesisSubs;
        Block genesis(0, genesisSubs, "0");
        chain.push_back(genesis);
    }

    void addBlock(const std::vector<MediaSubmission>& submissions) {
        const Block& prev = chain.back();
        Block newBlock(chain.size(), submissions, prev.hash);

        // Simple mining: proof-of-memory and hash starting with "0000"
        while (true) {
            if (proofOfMemory(5)) { // 5MB memory proof (adjust as needed)
                newBlock.hash = newBlock.calculateHash();
                if (newBlock.hash.substr(0, 4) == "0000") {
                    break;
                }
            }
            ++newBlock.nonce;
        }
        chain.push_back(newBlock);
        std::cout << "Block " << newBlock.index << " added. Hash: " << newBlock.hash << std::endl;
    }

    void print() const {
        for (const auto& block : chain) {
            std::cout << "Block #" << block.index << "\n"
                      << "  Timestamp: " << block.timestamp << "\n"
                      << "  PreviousHash: " << block.previousHash << "\n"
                      << "  Hash: " << block.hash << "\n"
                      << "  Nonce: " << block.nonce << "\n"
                      << "  Submissions: " << block.submissions.size() << "\n";
            for (const auto& m : block.submissions)
                std::cout << "    - " << m.mediaType << " by " << m.userPublicKey << " (" << m.mediaHash << ")\n";
            std::cout << std::endl;
        }
    }

private:
    std::vector<Block> chain;
};

// --- Example usage ---
int main() {
    Blockchain bc;

    // Add a block with some submissions
    std::vector<MediaSubmission> submissions = {
        {"user1_pubkey", "QmHashMeme", "meme"},
        {"user2_pubkey", "QmHashImage", "image"},
        {"user3_pubkey", "QmHashVid", "video"}
    };
    bc.addBlock(submissions);

    // Add a block with text submission
    std::vector<MediaSubmission> submissions2 = {
        {"user4_pubkey", "QmHashText", "text"}
    };
    bc.addBlock(submissions2);

    bc.print();
    return 0;
}