import datetime
import sys

# Store the next available id for all new notes
last_id = 0


class Note:
    '''Represent a note in the notebook. Match against a
    string in searches and store tags for each note.'''

    def __init__(self, memo, tags=""):
        '''initialize a note with memo and optional
         space-separated tags. Automatically set the note's
         creation date and a unique id.'''

        self.memo = memo
        self.tags = tags
        self.creation_date = datetime.date.today()
        global last_id
        last_id += 1
        self.id = last_id

    def match(self, filter):
        '''Determine if this note matches the filter
         text. Return True if it matches, False otherwise.

         Search is case sensitive and matches both text and
         tags.'''
        return filter in self.memo or filter in self.tags


class Notebook:
    '''Represent a collection of notes that can be tagged,
     modified, and searched.'''

    def __init__(self):
        '''Initialize a notebook with an empty list.'''
        self.notes = []

    def new_note(self, memo, tags=""):
        '''Create a new note and add it to the list.'''
        self.notes.append(Note(memo, tags))

    def _find_note(self, note_id):
        '''Locate the note with the given id.'''
        for note in self.notes:
            if str(note.id) == str(note_id):
                return note
        return None

    def modify_memo(self, note_id, memo):
        """Find the note with the given id and change its
         memo to the given value."""
        note = self._find_note(note_id)
        if note:
            note.memo = memo
            return True
        return False

    def modify_tags(self, note_id, tags):
        """Find the note with the given id and change its
         tags to the given value."""
        for note in self.notes:
            if note.id == note_id:
                note.tags = tags
                break

    def search(self, filter):
        """Find all notes that match the given filter
         string."""
        return [note for note in self.notes if note.match(filter)]


notebook = Notebook()


class Menu:
    '''Display a menu and respond to choices when run.'''

    def __init__(self):
        global notebook
        self.choices = {
            "1": self.show_notes,
            "2": self.search_notes,
            "3": self.add_note,
            "4": self.modify_note,
            "5": self.quit
        }

    def display_menu(self):
        print("""
        Notebook Menu
        1. Show all Notes
        2. Search Notes
        3. Add Note
        4. Modify Note
        5. Quit
        """)

    def run(self):
        '''Display the menu and respond to choices.'''

        while True:
            self.display_menu()
            choice = input("Enter an option: ")
            action = self.choices.get(choice)
            if action:
                action()
            else:
                print("{0} is not a valid choice.".format(choice))

    def show_notes(self, notes=None):
        global notebook
        if not notes:
            notes = notebook.notes
        for note in notes:
            print("{0}: {1}\n{2}".format(note.id, note.tags, note.memo))

    def search_notes(self):
        global notebook
        filter = input("Search for: ")
        notes = notebook.search(filter)
        self.show_notes(notes)

    def add_note(self):
        global notebook
        memo = input("Enter a memo: ")
        notebook.new_note(memo)
        print("Your note has been added.")

    def modify_note(self):
        global notebook
        id = input("Enter a note id: ")
        memo = input("Enter a memo: ")
        tags = input("Enter tags: ")
        if memo:
            notebook.modify_memo(id, memo)
        if tags:
            notebook.modify_tags(id, tags)

    def quit(self):
        print("Thank you for using notebook today.")
        sys.exit(0)
