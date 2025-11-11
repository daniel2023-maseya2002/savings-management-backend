# chatbot/trainer.py
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer, ListTrainer

BOT_NAME = "CreditJamboBot"

def train_bot():
    bot = ChatBot(
        BOT_NAME,
        storage_adapter="chatterbot.storage.SQLStorageAdapter",
        database_uri="sqlite:///db.sqlite3",  # uses project DB (adjust if using Postgres)
    )
    corpus_trainer = ChatterBotCorpusTrainer(bot)
    corpus_trainer.train("chatterbot.corpus.english")  # comment out after first run

    # Optional small custom QA:
    custom = [
        "Hi",
        "Hello! How can I help you with your savings?",
        "How do I deposit?",
        "Go to the deposit page, fill the amount and confirm — I can open it for you.",
    ]
    list_trainer = ListTrainer(bot)
    list_trainer.train(custom)

if __name__ == "__main__":
    train_bot()
