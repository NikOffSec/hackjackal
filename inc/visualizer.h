#pragma once
#include <GLFW/glfw3.h>
#include <atomic>
#include <memory>
#include <search.h>
#include <string>
#include <thread>
#include <vector>

enum class Screen {
  Menu,
  Credits,
  Loading,
  Idle,
  Search,
  Result,
};

float randf(float a, float b);
int randi(int a, int b);
char randGlyph();

class Visualizer {
public:
  Visualizer(GLuint headOpen, GLuint headClosed);
  ~Visualizer();

  // reads the records and builds the trees on a worker thread
  void startLoading(const std::string &dataDir);
  bool loadingDone() const { return loaded; }
  std::string loadingStatus() const;

  // the whole screen starts scrambled and decrypts from the center outwards
  void beginReveal();

  // draws the current screen, call between Begin("##main") and End
  void draw(Screen &screen);
  // the result windows, call after End so they stay on top
  void drawWindows(Screen &screen);

private:
  struct RevealChar {
    size_t start;
    size_t length;
    float revealAt;
  };

  void drawIdle();
  void drawSearch(Screen &screen);
  void drawResult();
  void drawSearchWindow(Screen &screen);
  void drawReveal();
  void drawPath(double mouth, double arc, float dim);
  void drawCrumbs(double mouth, double along);
  void drawHead(double mouth, double arc, const HopState &hop, double t);

  void startSearch(Screen &screen);
  void startFake(Screen &screen, size_t nodes, bool found);
  void beginAnimation(Screen &screen);
  void finishAnimation(Screen &screen);
  void openDecrypt(std::string text);
  void drawDecrypt();
  void drawMatchList();
  std::string revealedText(float t) const;

  double worldX(double s) const;
  double worldY(double s) const;

  GLuint headOpen, headClosed;

  std::thread worker;
  std::atomic<bool> loaded{false};
  std::atomic<size_t> feedsDone{0}, feedsTotal{0};
  std::unique_ptr<CveStore> store;
  std::string loadError;

  TreeKind treeKind = TreeKind::RedBlack;
  KeyKind keyKind = KeyKind::Date;
  char keyBuf[256] = "";
  std::string inputError;
  bool focusInput = false;
  float searchBottom = 0.0f;

  SearchResult result;
  std::vector<int> pathX;
  bool colored = false;
  bool fakeFound = false;

  double animStart = 0.0;
  double landedAt = 0.0;
  double camX = 0.0, camY = 0.0;
  bool facingLeft = false;
  size_t selected = 0;

  std::string decryptText;
  std::string decryptTitle;
  std::vector<RevealChar> decryptChars;
  double decryptStart = 0.0;
  float decryptDoneAt = 0.0f;
  bool decryptOpen = false;

  std::vector<float> revealAt; // one per cell of the character grid
  int revealCols = 0, revealRows = 0;
  double revealStart = 0.0;
  float revealDoneAt = 0.0f;
  bool revealing = false;
};
