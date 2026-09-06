#include "vpath.h"

#include <cmath>
#include <cstdio>
#include <limits>

namespace {

bool Check(float count, bool polygon, float roundness, bool valid) {
    VPath path;
    // An ignored shape must also leave existing geometry intact.
    path.addRect(VRectF(0, 0, 10, 10));
    const auto before = path.points();
    const auto elements = path.elements();
    if (polygon) {
        path.addPolygon(count, 20, roundness, 0, 0, 0);
    } else {
        path.addPolystar(count, 10, 20, roundness, roundness, 0, 0, 0);
    }
    if (valid) {
        if (path.points().size() <= before.size()) return false;
        for (const auto &point : path.points()) {
            if (!std::isfinite(point.x()) || !std::isfinite(point.y())) return false;
        }
    } else {
        if (path.elements() != elements || path.points().size() != before.size()) return false;
        for (auto i = size_t(0); i != before.size(); ++i) {
            if (path.points()[i].x() != before[i].x()
                || path.points()[i].y() != before[i].y()) return false;
        }
    }
    return true;
}

} // namespace

int main() {
    const auto inf = std::numeric_limits<float>::infinity();
    const auto nan = std::numeric_limits<float>::quiet_NaN();
    for (const auto polygon : { false, true }) {
        for (const auto roundness : { 0.f, 25.f }) {
            for (const auto count : { -5.f, -0.5f, 0.f, 0.5f, nan, inf, -inf,
                    10001.f, 1e20f, std::numeric_limits<float>::max() }) {
                if (!Check(count, polygon, roundness, false)) return 1;
            }
            for (const auto count : { 1.f, 3.f, 5.f, 5.5f, 10000.f }) {
                if (!Check(count, polygon, roundness, true)) return 2;
            }
        }
    }
    std::puts("Lottie polystar/polygon regression: 60 cases passed.");
}
