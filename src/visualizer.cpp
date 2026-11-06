#include "imgui.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <exception>
#include <format>
#include <utility>
#include <visualizer.h>

static constexpr float NODE_R = 42.0f;
static constexpr double NODE_DX = 70.0;
static constexpr double NODE_DY = 110.0;
static constexpr float HEAD_SIZE = 220.0f;
static constexpr float MOUTH_U = 0.68f; // middle of the open jaws in the sprite
static constexpr float MOUTH_V = 0.58f;
static constexpr float HEAD_TILT = 0.75f;
static constexpr double HOP_H = 30.0;
static constexpr double CHEW_H = 8.0;
static constexpr double LAND_PHASE = 0.7;
static constexpr float CRUMB_LIFE = 1.1f;
static constexpr uint32_t CRUMBS = 7;
static constexpr int DRAW_RANGE = 20;
static constexpr int TRAIL_COPIES = 6;
static constexpr double TRAIL_STEP = 0.12;
static constexpr double CAM_MAX_LAG = 1.5;
static constexpr double SHAKE_TIME = 0.6;
static constexpr float PI = 3.14159265f;
static constexpr float SEARCH_W = 340.0f;
static constexpr float REVEAL_SPREAD = 1.3f; // center to corner, in seconds
static constexpr float REVEAL_JITTER = 0.35f;
static constexpr float REVEAL_FRONT = 0.12f;

static ImU32 shade(int r, int g, int b, float f, int a = 255) {
  return IM_COL32((int)(r * f), (int)(g * f), (int)(b * f), a);
}

static void pushTheme() {
  ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.02f, 0.02f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,
                        ImVec4(0.25f, 0.04f, 0.05f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_FrameBgActive,
                        ImVec4(0.35f, 0.05f, 0.07f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(0.86f, 0.08f, 0.12f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.55f, 0.06f, 0.09f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_TitleBg, ImVec4(0.12f, 0.02f, 0.03f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_TitleBgActive,
                        ImVec4(0.40f, 0.05f, 0.07f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0.30f, 0.04f, 0.06f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_HeaderHovered,
                        ImVec4(0.45f, 0.05f, 0.08f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_HeaderActive,
                        ImVec4(0.70f, 0.08f, 0.10f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ResizeGrip, ImVec4(0.40f, 0.05f, 0.07f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ResizeGripHovered,
                        ImVec4(0.60f, 0.07f, 0.09f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ResizeGripActive,
                        ImVec4(0.80f, 0.09f, 0.11f, 1.0f));
}

static void popTheme() { ImGui::PopStyleColor(13); }

Visualizer::Visualizer(GLuint headOpen, GLuint headClosed)
    : headOpen(headOpen), headClosed(headClosed) {}

Visualizer::~Visualizer() {
  if (worker.joinable())
    worker.join();
}

void Visualizer::startLoading(const std::string &dataDir) {
  if (worker.joinable())
    return;
  worker = std::thread([this, dataDir] {
    try {
      auto loading = std::make_unique<CveStore>();
      loading->records =
          loadYearFeeds(dataDir, [this](size_t done, size_t total) {
            feedsDone = done;
            feedsTotal = total;
          });
      loading->build();
      store = std::move(loading);
    } catch (const std::exception &e) {
      loadError = e.what();
    }
    loaded = true;
  });
}

std::string Visualizer::loadingStatus() const {
  size_t total = feedsTotal;
  if (total == 0)
    return "";
  if (feedsDone < total)
    return std::format("reading feed {} of {}", feedsDone + 1, total);
  return "building trees";
}

void Visualizer::draw(Screen &screen) {
  pushTheme();
  if (screen == Screen::Idle)
    drawIdle();
  else if (screen == Screen::Search)
    drawSearch(screen);
  else if (screen == Screen::Result)
    drawResult();
  popTheme();
}

void Visualizer::drawIdle() {
  drawHead(0.0, 0.0, HopState{0, 0.0, false, true, 0.0}, 0.0);

  const char *hint = "use the search menu to find a CVE";
  ImVec2 wp = ImGui::GetWindowPos();
  ImVec2 ws = ImGui::GetWindowSize();
  ImVec2 size = ImGui::CalcTextSize(hint);
  ImGui::GetWindowDrawList()->AddText(
      ImVec2(wp.x + (ws.x - size.x) * 0.5f, wp.y + ws.y * 0.5f + 90.0f),
      IM_COL32(150, 130, 130, 255), hint);
}

void Visualizer::drawSearchWindow(Screen &screen) {
  const ImGuiViewport *vp = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + 30.0f, vp->WorkPos.y + 30.0f),
                          ImGuiCond_FirstUseEver);
  ImGui::Begin("search", nullptr,
               ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
                   ImGuiWindowFlags_AlwaysAutoResize);

  ImGui::TextUnformatted("Tree");
  if (ImGui::RadioButton("Red-Black", treeKind == TreeKind::RedBlack))
    treeKind = TreeKind::RedBlack;
  ImGui::SameLine();
  if (ImGui::RadioButton("Splay", treeKind == TreeKind::Splay))
    treeKind = TreeKind::Splay;

  ImGui::TextUnformatted("Key");
  if (ImGui::RadioButton("Date", keyKind == KeyKind::Date)) {
    keyKind = KeyKind::Date;
    inputError.clear();
  }
  ImGui::SameLine();
  if (ImGui::RadioButton("CPE", keyKind == KeyKind::Cpe)) {
    keyKind = KeyKind::Cpe;
    inputError.clear();
  }

  ImGui::Spacing();
  ImGui::TextUnformatted(keyKind == KeyKind::Date
                             ? "YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS"
                             : "product:version, like openssl:1.0.2");
  if (focusInput) {
    ImGui::SetKeyboardFocusHere();
    focusInput = false;
  }
  ImGui::SetNextItemWidth(SEARCH_W);
  bool submit = ImGui::InputText("##key", keyBuf, sizeof(keyBuf),
                                 ImGuiInputTextFlags_EnterReturnsTrue);

  ImGui::BeginDisabled(!store);
  submit = ImGui::Button("Search", ImVec2(SEARCH_W, 40.0f)) || submit;
  ImGui::EndDisabled();

  if (submit && store)
    startSearch(screen);

  ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + SEARCH_W);
  if (!store)
    ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f),
                       "No data: %s. Run scripts/download_nvd.py",
                       loadError.c_str());
  else if (!inputError.empty())
    ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "%s",
                       inputError.c_str());
  else
    ImGui::TextDisabled("%zu CVEs loaded", store->records.size());
  ImGui::PopTextWrapPos();

  if (screen == Screen::Search) {
    HopState hop = hopAt(ImGui::GetTime() - animStart, result.path.size() - 1);
    ImGui::Text("node %zu / %zu", std::min(hop.node + 1, result.path.size()),
                result.path.size());
    ImGui::TextDisabled("space or click to skip");
  } else if (screen == Screen::Result) {
    ImGui::Text("visited %zu nodes in %.1f \xC2\xB5s", result.path.size(),
                result.micros);
  }

  searchBottom = ImGui::GetWindowPos().y + ImGui::GetWindowSize().y;

#ifdef DEBUG_KEYS
  // F1 is 20 nodes and F2 is 300000, hold shift for the not found ending
  bool missing = ImGui::GetIO().KeyShift;
  if (ImGui::IsKeyPressed(ImGuiKey_F1, false))
    startFake(screen, 20, !missing);
  if (ImGui::IsKeyPressed(ImGuiKey_F2, false))
    startFake(screen, 300000, !missing);
#endif

  ImGui::End();
}

void Visualizer::beginReveal() {
  revealCols = revealRows = 0;
  revealStart = ImGui::GetTime();
  revealing = true;
  focusInput = true;
}

void Visualizer::drawReveal() {
  ImVec2 pos = ImGui::GetMainViewport()->Pos;
  ImVec2 size = ImGui::GetMainViewport()->Size;
  float cellW = ImGui::CalcTextSize("W").x;
  float cellH = ImGui::GetFontSize();
  int cols = (int)std::ceil(size.x / cellW);
  int rows = (int)std::ceil(size.y / cellH);

  if (cols != revealCols || rows != revealRows) {
    revealCols = cols;
    revealRows = rows;
    revealAt.resize((size_t)cols * rows);
    revealDoneAt = 0.0f;
    float farthest = std::hypot(size.x, size.y) * 0.5f;
    for (int y = 0; y < rows; y++) {
      for (int x = 0; x < cols; x++) {
        float dist =
            std::hypot(x * cellW - size.x * 0.5f, y * cellH - size.y * 0.5f);
        float at = dist / farthest * REVEAL_SPREAD + randf(0.0f, REVEAL_JITTER);
        revealAt[(size_t)y * cols + x] = at;
        revealDoneAt = std::max(revealDoneAt, at);
      }
    }
  }

  float t = (float)(ImGui::GetTime() - revealStart);
  if (t >= revealDoneAt) {
    revealing = false;
    return;
  }

  ImDrawList *dl = ImGui::GetForegroundDrawList();
  for (int y = 0; y < rows; y++) {
    for (int x = 0; x < cols; x++) {
      float left = revealAt[(size_t)y * cols + x] - t;
      if (left <= 0.0f)
        continue;
      ImVec2 p(pos.x + x * cellW, pos.y + y * cellH);
      dl->AddRectFilled(p, ImVec2(p.x + cellW, p.y + cellH),
                        IM_COL32(0, 0, 0, 255));
      char glyph = randGlyph();
      // the cells about to open up glow so the edge reads as it moves out
      ImU32 col = left < REVEAL_FRONT ? IM_COL32(255, 180, 180, 255)
                                      : IM_COL32(220, 20, 30, 220);
      dl->AddText(p, col, &glyph, &glyph + 1);
    }
  }
}

void Visualizer::startSearch(Screen &screen) {
  std::string query = trimmed(keyBuf);
  if (keyKind == KeyKind::Date) {
    int64_t lo, hi;
    if (!parseDateQuery(query, lo, hi)) {
      inputError = "That isn't a valid date";
      return;
    }
  } else if (query.empty()) {
    inputError = "Type a product:version key first";
    return;
  }

  inputError.clear();
  result = runSearch(*store, treeKind, keyKind, query);
  colored = treeKind == TreeKind::RedBlack;
  fakeFound = false;
  beginAnimation(screen);
}

void Visualizer::startFake(Screen &screen, size_t nodes, bool found) {
  result = SearchResult{};
  colored = treeKind == TreeKind::RedBlack;
  result.path = fakePath(nodes, colored, (uint32_t)randi(0, 1 << 30));
  fakeFound = found;
  beginAnimation(screen);
}

void Visualizer::beginAnimation(Screen &screen) {
  pathX.resize(result.path.size());
  int x = 0;
  for (size_t i = 0; i < result.path.size(); i++) {
    if (i > 0)
      x += result.path[i].wentLeft ? -1 : 1;
    pathX[i] = x;
  }

  camX = camY = 0.0;
  facingLeft = false;
  selected = SIZE_MAX;
  decryptOpen = false;
  animStart = ImGui::GetTime();
  screen = Screen::Search;
  if (result.path.empty())
    finishAnimation(screen);
}

void Visualizer::finishAnimation(Screen &screen) {
  screen = Screen::Result;
  landedAt = ImGui::GetTime();
  if (result.path.size() > 1)
    facingLeft = result.path.back().wentLeft;
  camX = worldX((double)result.path.size());
  camY = worldY((double)result.path.size());

  if (fakeFound)
    openDecrypt("FAKE-PATH\n\nDebug path with " +
                std::to_string(result.path.size()) +
                " nodes.\nNothing was searched, this only tests the animation "
                "and the decrypt window.\n");
  else if (result.matches.size() == 1) {
    selected = 0;
    openDecrypt(buildCveText(store->records[result.matches[0]]));
  }
}

double Visualizer::worldX(double s) const {
  if (pathX.empty())
    return 0.0;
  double last = (double)(pathX.size() - 1);
  s = std::clamp(s, 0.0, last);
  size_t i = (size_t)s;
  double f = s - (double)i;
  double x = pathX[i];
  if (i + 1 < pathX.size())
    x += (pathX[i + 1] - x) * f;
  return x * NODE_DX;
}

double Visualizer::worldY(double s) const {
  if (pathX.empty())
    return 0.0;
  return std::clamp(s, 0.0, (double)(pathX.size() - 1)) * NODE_DY;
}

// where the mouth is along the path, it gets to the next node while the jaws
// are still open and spends the rest of the hop chewing
static double mouthAt(const HopState &hop, size_t hops) {
  if (hop.done)
    return (double)hops + 1.0;
  if (hop.fast)
    return (double)hop.node + hop.phase;
  double p = std::min(1.0, hop.phase / LAND_PHASE);
  return (double)hop.node + p * p * (3.0 - 2.0 * p);
}

static double hopArc(const HopState &hop) {
  if (hop.fast || hop.done)
    return 0.0;
  if (hop.phase < LAND_PHASE)
    return std::sin(hop.phase / LAND_PHASE * PI) * HOP_H;
  return -std::sin((hop.phase - LAND_PHASE) / (1.0 - LAND_PHASE) * PI) * CHEW_H;
}

// 0 while a node is out of reach, 1 once it's been swallowed
static float eaten(int i, double mouth) {
  double p = i == 0 ? mouth / 0.25 : (mouth - (i - 0.35)) / 0.35;
  p = std::clamp(p, 0.0, 1.0);
  return (float)(p * p * (3.0 - 2.0 * p));
}

void Visualizer::drawPath(double mouth, double arc, float dim) {
  if (result.path.empty())
    return;

  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 wp = ImGui::GetWindowPos();
  ImVec2 ws = ImGui::GetWindowSize();
  double originX = wp.x + ws.x * 0.5 - camX;
  double originY = wp.y + ws.y * 0.5 - camY;

  auto screenAt = [&](size_t i) {
    return ImVec2((float)(originX + pathX[i] * NODE_DX),
                  (float)(originY + (double)i * NODE_DY));
  };
  ImVec2 mouthPos((float)(originX + worldX(mouth)),
                  (float)(originY + worldY(mouth) - arc));

  int count = (int)result.path.size();
  int head = (int)mouth;
  int first = std::max(0, head - DRAW_RANGE);
  int last = std::min(count - 1, head + DRAW_RANGE);

  for (int i = first; i < std::min(last + 1, count - 1); i++) {
    ImVec2 a = screenAt(i), b = screenAt(i + 1);
    dl->AddLine(a, b, shade(220, 20, 30, (i < head ? 0.3f : 1.0f) * dim), 2.0f);
    ImVec2 stub(a.x + (a.x - b.x), b.y);
    dl->AddLine(a, stub, IM_COL32(220, 20, 30, (int)(40 * dim)), 1.0f);
  }

  for (int i = first; i <= last; i++) {
    float e = eaten(i, mouth);
    ImVec2 c = screenAt(i);
    if (i < count - 1) {
      ImVec2 next = screenAt(i + 1);
      dl->AddCircle(ImVec2(c.x + (c.x - next.x), next.y), NODE_R * 0.5f,
                    IM_COL32(220, 20, 30, (int)(60 * dim)), 24);
    }

    const PathStep &step = result.path[i];
    auto fillAt = [&](float f, int a) {
      return !colored   ? shade(55, 55, 55, f, a)
             : step.red ? shade(170, 20, 30, f, a)
                        : shade(18, 18, 18, f, a);
    };

    // what's left behind once the node is gone
    if (e > 0.0f) {
      dl->AddCircleFilled(c, NODE_R, fillAt(0.25f * dim, (int)(255 * e)), 32);
      dl->AddCircle(c, NODE_R, shade(220, 20, 30, 0.3f * dim, (int)(255 * e)),
                    32, 1.0f);
    }

    // the node itself shrinks and gets pulled into the mouth
    if (e < 1.0f) {
      ImVec2 at(c.x + (mouthPos.x - c.x) * e, c.y + (mouthPos.y - c.y) * e);
      float r = NODE_R * (1.0f - e * 0.9f);
      dl->AddCircleFilled(at, r, fillAt(dim, 255), 32);
      dl->AddCircle(at, r, shade(220, 20, 30, dim), 32, 2.0f);
    }

    const char *text = step.label.c_str();
    ImVec2 size = ImGui::CalcTextSize(text);
    dl->AddText(ImVec2(c.x - size.x * 0.5f, c.y - size.y * 0.5f),
                shade(242, 217, 217, (1.0f - e * 0.65f) * dim), text);
  }
}

// bits flying off the last few nodes which are seeded by index so they don't
// flicker
void Visualizer::drawCrumbs(double mouth, double along) {
  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 wp = ImGui::GetWindowPos();
  ImVec2 ws = ImGui::GetWindowSize();
  double originX = wp.x + ws.x * 0.5 - camX;
  double originY = wp.y + ws.y * 0.5 - camY;

  int head = (int)mouth;
  int last = std::min(head, (int)result.path.size() - 1);
  for (int i = std::max(0, head - 2); i <= last; i++) {
    float age = (float)(along - (i - 0.3)) / CRUMB_LIFE;
    if (age <= 0.0f || age >= 1.0f)
      continue;
    float x = (float)(originX + pathX[i] * NODE_DX);
    float y = (float)(originY + i * NODE_DY);
    ImU32 col = !colored || !result.path[i].red
                    ? IM_COL32(150, 150, 150, (int)(230 * (1.0f - age)))
                    : IM_COL32(220, 30, 40, (int)(230 * (1.0f - age)));
    for (uint32_t k = 0; k < CRUMBS; k++) {
      uint32_t h = ((uint32_t)i * 2654435761u) ^ (k * 40503u * 2654435761u);
      float angle = (float)(h % 628) * 0.01f;
      float dist = (40.0f + (float)(h >> 24) * 0.35f) * age;
      dl->AddCircleFilled(
          ImVec2(x + std::cos(angle) * dist,
                 y + std::sin(angle) * dist + 90.0f * age * age),
          2.0f + (float)(k % 3), col, 8);
    }
  }
}

void Visualizer::drawHead(double mouth, double arc, const HopState &hop,
                          double t) {
  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 wp = ImGui::GetWindowPos();
  ImVec2 ws = ImGui::GetWindowSize();
  double originX = wp.x + ws.x * 0.5 - camX;
  double originY = wp.y + ws.y * 0.5 - camY;
  float cosT = std::cos(HEAD_TILT), sinT = std::sin(HEAD_TILT);

  // the sprite is placed by its mouth and tilted to point down the path
  auto drawAt = [&](double m, double up, GLuint tex, ImU32 tint) {
    ImVec2 mouthPos((float)(originX + worldX(m)),
                    (float)(originY + worldY(m) - up));
    auto corner = [&](float u, float v) {
      float lx = (u - MOUTH_U) * HEAD_SIZE, ly = (v - MOUTH_V) * HEAD_SIZE;
      float x = lx * cosT - ly * sinT, y = lx * sinT + ly * cosT;
      return ImVec2(mouthPos.x + (facingLeft ? -x : x), mouthPos.y + y);
    };
    dl->AddImageQuad((ImTextureID)(intptr_t)tex, corner(0, 0), corner(1, 0),
                     corner(1, 1), corner(0, 1), ImVec2(0, 0), ImVec2(1, 0),
                     ImVec2(1, 1), ImVec2(0, 1), tint);
  };

  if (hop.fast) {
    GLuint tex = std::fmod(t, 0.1) < 0.05 ? headOpen : headClosed;
    for (int k = TRAIL_COPIES; k >= 1; k--) {
      double back = std::max(0.0, mouth - k * TRAIL_STEP);
      float fade = (1.0f - (float)k / (TRAIL_COPIES + 1)) * (float)hop.fastLeft;
      drawAt(back, 0.0, tex, IM_COL32(255, 80, 80, (int)(110 * fade)));
    }
    drawAt(mouth, 0.0, tex, IM_COL32_WHITE);
    return;
  }

  bool open = !hop.done && hop.phase < LAND_PHASE;
  drawAt(mouth, arc, open ? headOpen : headClosed, IM_COL32_WHITE);
}

void Visualizer::drawSearch(Screen &screen) {
  double t = ImGui::GetTime() - animStart;
  size_t hops = result.path.size() - 1;
  HopState hop = hopAt(t, hops);
  double mouth = mouthAt(hop, hops);
  double arc = hopArc(hop);

  if (hop.node < hops)
    facingLeft = result.path[hop.node + 1].wentLeft;

  double dt = ImGui::GetIO().DeltaTime;
  double follow = std::min(1.0, dt * 8.0);
  camX += (worldX(mouth) - camX) * follow;
  camY += (worldY(mouth) - camY) * follow;
  // at full speed the formula would leave the head thousands of nodes
  // off screen so we compensate
  camX = std::clamp(camX, worldX(mouth) - NODE_DX * CAM_MAX_LAG,
                    worldX(mouth) + NODE_DX * CAM_MAX_LAG);
  camY = std::clamp(camY, worldY(mouth) - NODE_DY * CAM_MAX_LAG,
                    worldY(mouth) + NODE_DY * CAM_MAX_LAG);

  double along = (double)hop.node + hop.phase;
  drawPath(mouth, arc, 1.0f);
  drawHead(mouth, arc, hop, t);
  drawCrumbs(mouth, along);

  // the windows on top keep their own clicks and space might be getting typed
  bool skip = (ImGui::IsKeyPressed(ImGuiKey_Space, false) &&
               !ImGui::GetIO().WantTextInput) ||
              (ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
               ImGui::IsWindowHovered());
  if (skip || hop.done)
    finishAnimation(screen);
}

void Visualizer::drawResult() {
  double end = (double)result.path.size();
  double since = ImGui::GetTime() - landedAt;
  bool found = fakeFound || !result.matches.empty();

  HopState landed{0, 0.0, false, true, 0.0};
  drawPath(end, 0.0, 0.8f);

  // the shake only moves the head so swap the camera just for that draw
  double restX = camX;
  if (!found && since < SHAKE_TIME)
    camX += std::sin(since * 70.0) * 14.0 * (1.0 - since / SHAKE_TIME);
  drawHead(end, 0.0, landed, since);
  camX = restX;

  if (!result.path.empty()) {
    // the head covers the last node, so its key goes underneath
    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 ws = ImGui::GetWindowSize();
    const char *key = result.path.back().label.c_str();
    ImVec2 size = ImGui::CalcTextSize(key);
    ImGui::GetWindowDrawList()->AddText(
        ImVec2(wp.x + ws.x * 0.5f - size.x * 0.5f,
               wp.y + ws.y * 0.5f + NODE_R + 8.0f),
        IM_COL32(242, 217, 217, 255), key);
  }

  if (!found) {
    ImGui::SetWindowFontScale(5.0f);
    const char *text = "NOT FOUND";
    ImVec2 ws = ImGui::GetWindowSize();
    ImGui::SetCursorPos(
        ImVec2((ws.x - ImGui::CalcTextSize(text).x) * 0.5f, ws.y * 0.15f));
    ImGui::TextColored(ImVec4(1.0f, 0.1f, 0.15f, 1.0f), "%s", text);
    ImGui::SetWindowFontScale(1.0f);
  }
}

void Visualizer::drawWindows(Screen &screen) {
  if (screen != Screen::Menu && screen != Screen::Loading &&
      screen != Screen::Credits) {
    pushTheme();
    drawSearchWindow(screen);
    if (screen == Screen::Result) {
      if (result.matches.size() > 1)
        drawMatchList();
      if (decryptOpen)
        drawDecrypt();
    }
    popTheme();
  }
  if (revealing)
    drawReveal();
}

void Visualizer::drawMatchList() {
  const ImGuiViewport *vp = ImGui::GetMainViewport();
  float top = searchBottom + 10.0f;
  ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + 30.0f, top),
                          ImGuiCond_Appearing);
  ImGui::SetNextWindowSize(
      ImVec2(SEARCH_W + 16.0f, vp->WorkPos.y + vp->WorkSize.y - top - 30.0f),
      ImGuiCond_Appearing);
  std::string title =
      std::format("{} matches###matches", result.matches.size());
  ImGui::Begin(title.c_str(), nullptr,
               ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
  ImGui::Text("visited %zu nodes in %.1f \xC2\xB5s", result.path.size(),
              result.micros);
  ImGui::Separator();

  ImGui::BeginChild("##list");
  ImGuiListClipper clipper;
  clipper.Begin((int)result.matches.size());
  while (clipper.Step()) {
    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
      const CveRecord &record = store->records[result.matches[i]];
      std::string row =
          std::format("{}  {}##{}", record.id,
                      formatDate(record.published).substr(0, 10), i);
      if (ImGui::Selectable(row.c_str(), selected == (size_t)i)) {
        selected = (size_t)i;
        openDecrypt(buildCveText(record));
      }
    }
  }
  ImGui::EndChild();
  ImGui::End();
}

void Visualizer::openDecrypt(std::string text) {
  decryptText = std::move(text);
  decryptTitle = decryptText.substr(0, decryptText.find('\n'));
  decryptChars.clear();
  decryptDoneAt = 0.0f;

  size_t i = 0;
  for (size_t at = 0; at < decryptText.size(); i++) {
    size_t length = 1;
    while (at + length < decryptText.size() &&
           (decryptText[at + length] & 0xC0) == 0x80)
      length++;
    float revealAt = (float)i * 0.004f + randf(0.0f, 0.6f);
    decryptChars.push_back({at, length, revealAt});
    decryptDoneAt = std::max(decryptDoneAt, revealAt);
    at += length;
  }

  decryptStart = ImGui::GetTime();
  decryptOpen = true;
}

std::string Visualizer::revealedText(float t) const {
  if (t >= decryptDoneAt)
    return decryptText;

  std::string out;
  out.reserve(decryptText.size());
  for (const RevealChar &c : decryptChars) {
    char first = decryptText[c.start];
    bool space =
        first == ' ' || first == '\n' || first == '\t' || first == '\r';
    if (space || t >= c.revealAt)
      out.append(decryptText, c.start, c.length);
    else
      out += randGlyph();
  }
  return out;
}

void Visualizer::drawDecrypt() {
  const ImGuiViewport *vp = ImGui::GetMainViewport();
  // off to the side so the node it landed on stays visible
  ImGui::SetNextWindowPos(
      ImVec2(vp->WorkPos.x + vp->WorkSize.x - 30.0f, vp->WorkPos.y + 70.0f),
      ImGuiCond_Appearing, ImVec2(1.0f, 0.0f));
  ImGui::SetNextWindowSize(ImVec2(780.0f, 700.0f), ImGuiCond_Appearing);
  std::string title = "decrypting " + decryptTitle + "###decrypt";
  if (ImGui::Begin(title.c_str(), &decryptOpen,
                   ImGuiWindowFlags_NoCollapse |
                       ImGuiWindowFlags_NoSavedSettings)) {
    ImGui::Text("visited %zu nodes in %.1f \xC2\xB5s", result.path.size(),
                result.micros);
    ImGui::Separator();
    ImGui::BeginChild("##text");
    ImGui::PushTextWrapPos(0.0f);
    std::string text = revealedText((float)(ImGui::GetTime() - decryptStart));
    ImGui::TextUnformatted(text.c_str());
    ImGui::PopTextWrapPos();
    ImGui::EndChild();
  }
  ImGui::End();
}
